%%
%% %CopyrightBegin%
%%
%% Copyright Ericsson AB 2011-2020. All Rights Reserved.
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%     http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%
%% %CopyrightEnd%
%%

-module(pubkey_ocsp_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("public_key/include/public_key.hrl").

%% Note: This directive should only be used in test suites.
-compile(export_all).

%%--------------------------------------------------------------------
%% Common Test interface functions -----------------------------------
%%--------------------------------------------------------------------
all() -> 
    [verify_ocsp_response_test, decode_ocsp_response_test, get_nonce_extn_test].

groups() -> 
    [].

%%--------------------------------------------------------------------
init_per_suite(Config) ->
    Config.

end_per_suite(_Config) ->
    ok.

%%--------------------------------------------------------------------

init_per_group(_GroupName, Config) ->
    Config.

end_per_group(_GroupName, Config) ->
    Config.

%%--------------------------------------------------------------------
init_per_testcase(_TestCase, Config) ->
    Config.

end_per_testcase(_TestCase, _Config) ->
    ok.

%%--------------------------------------------------------------------
%% Test Cases --------------------------------------------------------
%%--------------------------------------------------------------------
verify_ocsp_response_test() ->
    [{doc, "Test pubkey_ocsp:verify_ocsp_response/3"}].
verify_ocsp_response_test(Config) when is_list(Config) ->
    LongTime = calendar:gregorian_days_to_date(calendar:date_to_gregorian_days(date())+15*365),
    Validity = {date(), LongTime},
    Subject = [{email, "tester@erlang.org"},
	       {city, "Stockholm"},
	       {country, "SE"},
	       {org, "erlang"},
	       {org_unit, "testing dep"}],

    % Issuing CA, with OCSP endpoint URL; key usage allows signing OCSP
    % responses directly
    AIA = [#'AccessDescription'{accessMethod = ?'id-pkix-ocsp',
        accessLocation = {uniformResourceIdentifier, "http://ocsp.example.org/responder"}}],
    IssuerExts = [{basic_constraints, 0},
        {key_usage, [keyCertSign, digitalSignature]},
        {?'id-ce-extKeyUsage', [?'id-kp-OCSPSigningPKIX1Implicit88'], true},
        {?'id-pe-authorityInfoAccess', AIA, false}],
    Issuer = erl_make_certs:make_cert([
        {validity, Validity},
		{subject, [{name, "Server CA"}|Subject]},
        {extensions, IssuerExts}]),

    % Sample server certificate (not needed yet, necessary for generating
    % OCSP requests in the future...
    % ServerExts = [{basic_constraints, false}],
    % Server = erl_make_certs:make_cert([
    %     {issuer, Issuer},
    %     {validity, Validity},
    %     {subject, [{name, "some.server.net"}|Subject]},
    %     {extensions, ServerExts}]),

    % Dedicated OCSP responder, issued by the CA
    ResponderExts = [{key_usage, [digitalSignature]},
        {?'id-ce-extKeyUsage', [?'id-kp-OCSPSigningPKIX1Implicit88'], true}],
    Responder = erl_make_certs:make_cert([
        {issuer, Issuer}, {validity, Validity},
        {subject, [{name, "OSCP Responder"}|Subject]},
        {extensions, ResponderExts}]),

    % Expired responder
    NotBefore = calendar:gregorian_days_to_date(calendar:date_to_gregorian_days(date())-365),
    NotAfter = calendar:gregorian_days_to_date(calendar:date_to_gregorian_days(date())-1),
    ExpiredResponder = erl_make_certs:make_cert([
        {issuer, Issuer},
        {validity, {NotBefore, NotAfter}},
        {subject, [{name, "OSCP Responder (expired)"}|Subject]},
        {extensions, ResponderExts}]),

    % Responder without necessary key usage / ext. key usage
    BadResponder = erl_make_certs:make_cert([
        {issuer, Issuer},
        {validity, Validity},
        {subject, [{name, "OSCP Responder (no OCSP key usage)"}|Subject]}]),

    % Self-signed responder, testing the case where no valid chain to the
    % issuer exists
    SelfSignedResponder = erl_make_certs:make_cert([
        {validity, Validity},
        {subject, [{name, "OSCP Responder (self signed)"}|Subject]},
        {extensions, ResponderExts}]),

    % Fake responder, testing the case where the responder appears to be issued
    % by the correct issuer, but the signature is invalid
    {_, OtherPrivateKey} = erl_make_certs:gen_rsa(64),
    BadIssuer = {element(1, Issuer), OtherPrivateKey},
    FakeResponder = erl_make_certs:make_cert([
        {issuer, BadIssuer},
        {validity, Validity},
        {subject, [{name, "OSCP Responder (wrong signature)"}|Subject]},
        {extensions, ResponderExts}]),

    IssuerCert = element(1, Issuer),
    CertID = cert_id(IssuerCert, element(1, Issuer)),
    Nonce = <<226,210,104,247,153,233,71,246>>,

    ct:pal("Check pubkey_ocsp:verify_ocsp_response/3~n"),
    OcspResponse1 = ocsp_response(CertID, good, Nonce, Responder),
    {ok, [#'SingleResponse'{}]} =
        pubkey_ocsp:verify_ocsp_response(OcspResponse1, IssuerCert, Nonce),

    OcspResponse2 = ocsp_response(CertID, good, Nonce, Issuer, [{certs, []}]),
    {ok, [#'SingleResponse'{}]} =
        pubkey_ocsp:verify_ocsp_response(OcspResponse2, IssuerCert, Nonce),

    {error, nonce_mismatch} =
        pubkey_ocsp:verify_ocsp_response(OcspResponse1, IssuerCert, <<1,2,3>>),

    {ResponderCert, _} = Responder,
    {_, BadPrivateKey} = erl_make_certs:gen_rsa(64),
    OcspResponse3 = ocsp_response(CertID, good, Nonce, {ResponderCert, BadPrivateKey}),
    {error, ocsp_response_bad_signature} =
        pubkey_ocsp:verify_ocsp_response(OcspResponse3, IssuerCert, Nonce),

    OcspResponse4 = ocsp_response(CertID, good, Nonce, Responder, [{certs, []}]),
    {error, ocsp_responder_cert_not_found} =
        pubkey_ocsp:verify_ocsp_response(OcspResponse4, IssuerCert, Nonce),

    OcspResponse5 = ocsp_response(CertID, good, Nonce, ExpiredResponder),
    {error, ocsp_response_bad_responder} =
        pubkey_ocsp:verify_ocsp_response(OcspResponse5, IssuerCert, Nonce),

    OcspResponse6 = ocsp_response(CertID, good, Nonce, BadResponder),
    {error, ocsp_response_bad_responder} =
        pubkey_ocsp:verify_ocsp_response(OcspResponse6, IssuerCert, Nonce),

    OcspResponse7 = ocsp_response(CertID, good, Nonce, SelfSignedResponder),
    {error, ocsp_response_bad_responder} =
        pubkey_ocsp:verify_ocsp_response(OcspResponse7, IssuerCert, Nonce),

    OcspResponse8 = ocsp_response(CertID, good, Nonce, FakeResponder),
    {error, ocsp_response_bad_responder} =
        pubkey_ocsp:verify_ocsp_response(OcspResponse8, IssuerCert, Nonce),

    ct:pal("pubkey_ocsp:verify_ocsp_response/3...ok~n").

decode_ocsp_response_test() ->
    [{doc, "Test pubkey_ocsp:decode_ocsp_response/1"}].
decode_ocsp_response_test(Config) when is_list(Config) ->
    OCSPResponseDer =
    <<48,130,7,6,10,1,0,160,130,6,255,48,130,6,251,6,9,43,6,1,5,5,7,48,1,1,4,130,6,
    236,48,130,6,232,48,130,1,11,161,129,137,48,129,134,49,17,48,15,6,3,85,4,3,
    12,8,98,46,115,101,114,118,101,114,49,19,48,17,6,3,85,4,11,12,10,69,114,108,
    97,110,103,32,79,84,80,49,20,48,18,6,3,85,4,10,12,11,69,114,105,99,115,115,
    111,110,32,65,66,49,11,48,9,6,3,85,4,6,19,2,83,69,49,18,48,16,6,3,85,4,7,12,
    9,83,116,111,99,107,104,111,108,109,49,37,48,35,6,9,42,134,72,134,247,13,1,9,
    1,22,22,112,101,116,101,114,64,101,114,105,120,46,101,114,105,99,115,115,111,
    110,46,115,101,24,15,50,48,50,48,48,52,50,56,48,56,51,50,48,53,90,48,81,48,
    79,48,58,48,9,6,5,43,14,3,2,26,5,0,4,20,227,147,252,182,155,101,129,45,194,
    162,22,93,127,46,112,193,196,28,241,232,4,20,99,34,37,88,164,188,98,22,125,
    252,71,72,246,115,141,222,108,19,122,168,2,1,7,128,0,24,15,50,48,50,48,48,52,
    50,56,48,56,51,50,48,53,90,161,25,48,23,48,21,6,9,43,6,1,5,5,7,48,1,2,4,8,
    226,210,104,247,153,233,71,246,48,13,6,9,42,134,72,134,247,13,1,1,11,5,0,3,
    130,1,1,0,85,82,43,226,38,172,139,105,77,248,24,250,244,154,2,174,232,141,52,
    93,102,37,177,31,59,105,104,242,117,238,102,93,61,56,24,47,69,169,184,234,
    109,204,5,64,109,101,23,197,234,6,250,223,95,175,131,138,227,66,123,199,182,
    57,102,47,221,72,112,208,1,4,128,209,235,108,64,209,31,128,37,130,176,132,
    203,119,24,188,187,254,8,167,54,80,28,208,26,118,236,149,184,182,25,236,252,
    158,253,167,143,114,14,184,198,144,51,195,44,16,38,255,112,124,81,201,255,
    132,143,98,119,135,23,232,10,184,54,150,227,131,212,81,101,158,152,82,252,
    156,28,30,163,203,145,11,179,105,230,187,132,119,186,189,67,198,165,48,106,
    114,75,151,128,108,28,44,121,195,162,222,25,45,99,46,84,116,125,51,72,191,
    250,186,71,78,21,222,219,232,143,233,226,56,163,23,51,170,69,152,223,0,63,8,
    236,219,175,18,165,88,166,125,71,31,53,40,12,133,64,250,30,190,113,10,187,38,
    171,17,210,170,126,198,232,195,224,228,1,246,75,140,139,121,229,17,153,115,
    199,68,227,171,176,163,117,171,160,130,4,193,48,130,4,189,48,130,4,185,48,
    130,3,161,160,3,2,1,2,2,1,9,48,13,6,9,42,134,72,134,247,13,1,1,5,5,0,48,129,
    131,49,14,48,12,6,3,85,4,3,12,5,111,116,112,67,65,49,19,48,17,6,3,85,4,11,12,
    10,69,114,108,97,110,103,32,79,84,80,49,20,48,18,6,3,85,4,10,12,11,69,114,
    105,99,115,115,111,110,32,65,66,49,11,48,9,6,3,85,4,6,19,2,83,69,49,18,48,16,
    6,3,85,4,7,12,9,83,116,111,99,107,104,111,108,109,49,37,48,35,6,9,42,134,72,
    134,247,13,1,9,1,22,22,112,101,116,101,114,64,101,114,105,120,46,101,114,105,
    99,115,115,111,110,46,115,101,48,30,23,13,50,48,48,52,50,56,48,56,51,50,48,
    53,90,23,13,51,48,48,51,48,55,48,56,51,50,48,53,90,48,129,134,49,17,48,15,6,
    3,85,4,3,12,8,98,46,115,101,114,118,101,114,49,19,48,17,6,3,85,4,11,12,10,69,
    114,108,97,110,103,32,79,84,80,49,20,48,18,6,3,85,4,10,12,11,69,114,105,99,
    115,115,111,110,32,65,66,49,11,48,9,6,3,85,4,6,19,2,83,69,49,18,48,16,6,3,85,
    4,7,12,9,83,116,111,99,107,104,111,108,109,49,37,48,35,6,9,42,134,72,134,247,
    13,1,9,1,22,22,112,101,116,101,114,64,101,114,105,120,46,101,114,105,99,115,
    115,111,110,46,115,101,48,130,1,34,48,13,6,9,42,134,72,134,247,13,1,1,1,5,0,
    3,130,1,15,0,48,130,1,10,2,130,1,1,0,188,248,42,161,172,252,200,52,180,217,
    145,59,193,72,33,176,213,106,37,81,119,251,205,254,70,196,171,127,79,157,147,
    235,14,61,25,162,207,134,25,239,35,62,57,10,214,115,231,71,203,226,198,73,
    223,222,199,165,82,67,33,78,176,116,241,192,97,169,143,164,219,152,40,115,
    229,242,128,97,98,183,217,199,35,127,146,94,20,115,0,250,200,39,9,255,230,
    216,80,140,6,133,251,39,96,240,176,184,34,1,134,247,126,237,255,130,170,98,
    242,140,104,105,95,48,75,115,135,229,89,191,180,179,123,198,232,228,220,249,
    113,86,186,212,176,194,66,14,164,236,219,138,254,80,57,118,232,163,192,94,78,
    224,100,124,206,199,81,105,54,222,26,245,170,147,184,192,237,77,143,154,180,
    79,42,107,75,77,81,215,19,75,8,160,106,199,196,66,53,16,233,184,175,85,167,
    148,12,232,248,113,61,89,14,156,199,128,83,40,214,228,83,9,36,72,188,25,29,
    47,172,78,114,191,120,240,227,234,255,194,61,132,57,1,141,131,227,64,152,209,
    205,63,24,172,223,194,254,97,133,255,192,133,148,237,178,115,2,3,1,0,1,163,
    130,1,49,48,130,1,45,48,9,6,3,85,29,19,4,2,48,0,48,11,6,3,85,29,15,4,4,3,2,5,
    224,48,29,6,3,85,29,14,4,22,4,20,63,72,140,0,84,13,114,48,50,31,9,241,231,
    177,20,184,8,114,244,29,48,129,179,6,3,85,29,35,4,129,171,48,129,168,128,20,
    99,34,37,88,164,188,98,22,125,252,71,72,246,115,141,222,108,19,122,168,161,
    129,140,164,129,137,48,129,134,49,17,48,15,6,3,85,4,3,12,8,101,114,108,97,
    110,103,67,65,49,19,48,17,6,3,85,4,11,12,10,69,114,108,97,110,103,32,79,84,
    80,49,20,48,18,6,3,85,4,10,12,11,69,114,105,99,115,115,111,110,32,65,66,49,
    18,48,16,6,3,85,4,7,12,9,83,116,111,99,107,104,111,108,109,49,11,48,9,6,3,85,
    4,6,19,2,83,69,49,37,48,35,6,9,42,134,72,134,247,13,1,9,1,22,22,112,101,116,
    101,114,64,101,114,105,120,46,101,114,105,99,115,115,111,110,46,115,101,130,
    1,1,48,27,6,3,85,29,17,4,20,48,18,130,16,104,111,115,116,46,101,120,97,109,
    112,108,101,46,99,111,109,48,33,6,3,85,29,18,4,26,48,24,129,22,112,101,116,
    101,114,64,101,114,105,120,46,101,114,105,99,115,115,111,110,46,115,101,48,
    13,6,9,42,134,72,134,247,13,1,1,5,5,0,3,130,1,1,0,86,112,29,225,102,143,193,
    55,126,115,187,208,118,153,111,177,160,121,55,33,184,60,27,111,40,7,93,241,9,
    226,40,125,181,36,173,116,190,43,187,52,254,50,229,222,56,215,132,67,217,174,
    121,24,94,240,163,56,12,36,212,2,40,94,102,126,206,52,40,32,218,59,86,166,
    238,137,144,90,57,211,141,81,32,102,215,180,59,133,125,208,199,166,81,35,49,
    24,88,100,127,90,145,237,150,249,227,123,120,98,230,12,106,72,201,127,54,94,
    164,204,23,158,3,230,232,181,95,251,98,6,28,115,46,153,241,233,254,152,176,
    114,12,148,24,234,185,204,177,189,70,14,73,181,232,245,63,226,14,138,249,101,
    56,222,188,78,127,191,174,232,182,207,67,162,111,248,192,202,65,96,237,206,
    52,220,63,50,108,82,185,169,29,148,30,75,74,16,156,229,166,96,102,214,145,77,
    225,218,180,54,109,61,62,119,144,231,72,105,61,201,245,219,192,63,160,242,
    247,112,64,199,65,248,252,59,145,150,212,151,166,223,237,121,135,13,122,111,
    22,117,115,166,64,143,10,40,13,5,240,22,38,235,32,107,194,41>>,

    ct:pal("Check pubkey_ocsp:decode_ocsp_response/1~n"),
    {ok, #'BasicOCSPResponse'{}} =
        pubkey_ocsp:decode_ocsp_response(OCSPResponseDer),
    ct:pal("pubkey_ocsp:decode_ocsp_response/1...ok~n").

get_nonce_extn_test() ->
    [{doc, "Test pubkey_ocsp:get_nonce_extn/3"}].
get_nonce_extn_test(Config) when is_list(Config) ->
    Nonce = <<226,210,104,247,153,233,71,246>>,

    NonceExtension =
    #'Extension'{
        extnID    = ?'id-pkix-ocsp-nonce',
        extnValue = Nonce
    },

    ct:pal("Check pubkey_ocsp:get_nonce_extn/1~n"),
    undefined =
        pubkey_ocsp:get_nonce_extn(undefined),
    NonceExtension =
        pubkey_ocsp:get_nonce_extn(Nonce),
    ct:pal("pubkey_ocsp:get_nonce_extn/1...ok~n").

%%
%% Candidate for moving into pubkey_ocsp?
%%

cert_id(Cert, IssuerCert) when is_binary(Cert) ->
    cert_id(public_key:der_decode('Certificate', Cert), IssuerCert);

cert_id(Cert, IssuerCert) when is_binary(IssuerCert) ->
    cert_id(Cert, public_key:der_decode('Certificate', IssuerCert));

cert_id(#'Certificate'{tbsCertificate = TBSCert},
        #'Certificate'{tbsCertificate = IssuerTBSCert}) ->
    {rdnSequence, IssuerName} = IssuerTBSCert#'TBSCertificate'.subject,
    IssuerNameDer = public_key:der_encode('RDNSequence', IssuerName),
    #'SubjectPublicKeyInfo'{
        subjectPublicKey = SubjectPublicKey
    } = IssuerTBSCert#'TBSCertificate'.subjectPublicKeyInfo,
    % TODO: support SHA2
    #'CertID'{hashAlgorithm = #'AlgorithmIdentifier'{algorithm = ?'id-sha1', parameters = <<5, 0>>},
              issuerNameHash = crypto:hash(sha, IssuerNameDer),
              issuerKeyHash = crypto:hash(sha, SubjectPublicKey),
              serialNumber = TBSCert#'TBSCertificate'.serialNumber}.

%
% Helpers
%

ocsp_response(CertID, Status, Nonce, {ResponderDer, ResponderKey}) ->
    ocsp_response(CertID, Status, Nonce, {ResponderDer, ResponderKey}, []).

ocsp_response(CertID, Status, Nonce, {ResponderDer, ResponderKey}, Opts) ->
    ResponderCert = public_key:pkix_decode_cert(ResponderDer, plain),
    PrivateKey = public_key:pem_entry_decode(ResponderKey),
    #'Certificate'{tbsCertificate = TBSCertificate} = ResponderCert,
    #'SubjectPublicKeyInfo'{
        subjectPublicKey = SubjectPublicKey
    } = TBSCertificate#'TBSCertificate'.subjectPublicKeyInfo,
    ResponderKeyHash = crypto:hash(sha, SubjectPublicKey),

    SingleResponse = #'SingleResponse'{
        certID = CertID,
        certStatus = {Status, 'NULL'},
        thisUpdate = "20200428083205Z",
        nextUpdate = asn1_NOVALUE},
    NonceExtension = #'Extension'{
        extnID    = ?'id-pkix-ocsp-nonce',
        extnValue = Nonce
    },
    ResponseData = #'ResponseData'{
        responderID = {byKey, ResponderKeyHash},
        producedAt = "20200428083205Z",
        responses = [SingleResponse],
        responseExtensions = [NonceExtension]
    },
    TBSResponseData = public_key:der_encode('ResponseData', ResponseData),
    Certs = proplists:get_value(certs, Opts, [ResponderCert]),
    BasicOCSPResponse = #'BasicOCSPResponse'{
        tbsResponseData = ResponseData,
        signatureAlgorithm = #'AlgorithmIdentifier'{algorithm = ?'sha256WithRSAEncryption', parameters = <<5, 0>>},
        signature = public_key:sign(TBSResponseData, sha256, PrivateKey),
        certs = Certs
    },
    BasicOCSPResponseDer = public_key:der_encode('BasicOCSPResponse', BasicOCSPResponse),
    OCSPResponse = #'OCSPResponse'{
        responseStatus = successful,
        responseBytes = #'ResponseBytes'{responseType = ?'id-pkix-ocsp-basic',
            response = BasicOCSPResponseDer}},
    public_key:der_encode('OCSPResponse', OCSPResponse).
