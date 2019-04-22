using ApnaPay_DataContract;
using Newtonsoft.Json;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;
using System.Configuration;
using System.Web;
using System.Data.SqlClient;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Text;
using ApnaPay_DataContract.AlankitGSTR1;

namespace ApnaPay.Controllers
{
    [LoggingAPIFilterAttribute]
    [LoggingAPIExceptionFilterAttribute]
    [RoutePrefix("api/v1")]
    public class GSTV1Controller : ApiController
    {
        IDictionary ErrorMsg = ConfigurationManager.GetSection("ErrorMessages") as IDictionary;
        public string GST_API_URL = ConfigurationManager.AppSettings["GST_API_URL"].ToString();
        public string MerchantStateID = "";
        public string MerchantGSTUserName = "";
        DataAccessLayer dal = new DataAccessLayer();
        ResponseClass baseResp = new ResponseClass();
        WCFWebRequest web = new WCFWebRequest();
        MyAuthorizationServerProvider UniqueTransactionID = new MyAuthorizationServerProvider();
        Dictionary<string, string> headers = new Dictionary<string, string>();
        DataTable dt;
        public string getSPResult = "";
        GST_Encryption encryption = new GST_Encryption();

        #region Generic Methods

        /// <summary>
        /// Get Merchant details by his ID
        /// </summary>
        /// <param name="merchantUID"></param>
        /// <returns></returns>
        public ResponseClass getMerchantDetails(int merchantUID)
        {
            Logging.LogInfo("Starts getMerchantDetails");

            SqlParameter[] para = new SqlParameter[2];
            para[0] = new SqlParameter("@merchantUID", SqlDbType.Int);
            para[0].Value = merchantUID;
            para[1] = new SqlParameter("@Result", SqlDbType.VarChar, 10);
            para[1].Direction = ParameterDirection.Output;

            dt = dal.executedtprocedure("usp_getMerchantInfoforGSTbyUID", para, true);
            getSPResult = Convert.ToString(para[1].Value);
            if (getSPResult == "69")
            {
                MerchantStateID = dt.Rows[0]["GSTN"].ToString();
                MerchantGSTUserName = dt.Rows[0]["gst_username"].ToString();
            }
            //MerchantStateID = "27";
            //MerchantGSTUserName = "MH_NT_TP249";

            baseResp.status = Convert.ToInt32(getSPResult);
            baseResp.message = "";
            baseResp.data = "[]";

            Logging.LogInfo("End getMerchantDetails");

            return baseResp;
        }

        public HttpResponseMessage GenericResponse(ResponseClass genericResp)
        {
            HttpResponseMessage resp = Request.CreateResponse();
            //if (ErrorMsg[genericResp.status.ToString()].ToString() == null)
            //{
            //    genericResp.status = 999;
            //}
            //genericResp.message = ErrorMsg[genericResp.status.ToString()].ToString();
            //genericResp.status = baseResp.status > 500 ? baseResp.status : 0;
            var BaseJson = JsonConvert.SerializeObject(genericResp);
            resp.Content = new StringContent(BaseJson, System.Text.Encoding.Default, "application/json");
            return resp;
        }

        /// <summary>
        /// Set Common headers for all API's
        /// </summary>
        /// <returns></returns>
        public Dictionary<string, string> setHeaders()
        {
            headers.Add("clientid", ConfigurationManager.AppSettings["clientid"].ToString());
            headers.Add("client-secret", ConfigurationManager.AppSettings["clientsecret"].ToString());
            headers.Add("Ocp-Apim-Subscription-Key", ConfigurationManager.AppSettings["OcpApimSubscriptionKey"].ToString());
            //headers.Add("ip-usr", HttpContext.Current.Request.Headers["HOST"]);
            headers.Add("ip-usr", "114.143.183.18");
            headers.Add("txn", UniqueTransactionID.genarateToken(15, 15));

            return headers;
        }

        public string decryptResponse(string rek, string recievedData, byte[] decryptedSek)
        {
            byte[] decryptREK = encryption.Decrypt(rek, decryptedSek);

            byte[] jsonData = encryption.Decrypt(recievedData, decryptREK);

            string json = Encoding.UTF8.GetString(jsonData);

            byte[] decodeJson = Convert.FromBase64String(json);

            return Encoding.UTF8.GetString(decodeJson);
        }

        #endregion

        #region GSTR API

        /// <summary>
        /// OTP Request API
        /// </summary>
        /// <param name="merchantUID"></param>
        /// <returns></returns>
        [HttpGet]
        [Route("GenerateOTP/{merchantUID}")]
        public HttpResponseMessage GenerateOTP(int merchantUID)
        {
            getMerchantDetails(merchantUID);
            setHeaders();
            headers.Add("state-cd", MerchantStateID.Substring(0, 2));
            string app_key = encryption.generateAppKey();

            if (app_key != "" || MerchantGSTUserName != "")
            {
                GST_OTP otp = new GST_OTP();
                otp.action = "OTPREQUEST";
                otp.app_key = app_key;
                otp.username = MerchantGSTUserName;

                var reqJson = JsonConvert.SerializeObject(otp);

                string response = web.callHTTPWebRequestforGST(GST_API_URL + "taxpayerapi/v0.3/dev/authenticate", reqJson, "POST", headers);

                Logging.LogInfo("GenerateOTP Response: \r\n" + response);

                var respJson = JsonConvert.DeserializeObject<dynamic>(response);

                if (respJson["status_cd"] == "1")
                {
                    baseResp.status = 0;
                    baseResp.message = "OTP generated successfully";
                    baseResp.data = app_key;
                }
                else
                {
                    baseResp.status = 501;
                    baseResp.message = respJson["error"]["message"];
                    baseResp.data = "";
                }
            }
            else
            {
                baseResp.status = 501;
                baseResp.message = "Missing parameters";
                baseResp.data = "";
            }
            return GenericResponse(baseResp);

        }

        /// <summary>
        /// API is invoked by the GSP application to issue authentication token by verifying username and OTP combination.
        /// </summary>
        /// <param name="dtl"></param>
        /// <returns></returns>
        [HttpPost]
        [Route("RequestforAuthorizationToken")]
        public HttpResponseMessage RequestforAuthorizationToken(GST_Auth_Token dtl)
        {
            Logging.LogInfo("RequestforAuthorizationToken Request: \r\n" + JsonConvert.SerializeObject(dtl));
            getMerchantDetails(Convert.ToInt32(dtl.username));
            setHeaders();
            headers.Add("state-cd", MerchantStateID.Substring(0, 2));

            if (dtl.app_key != "" || MerchantGSTUserName != "" || dtl.otp != "")
            {
                string encryptedOTP = encryption.Encrypt(dtl.otp, ConfigurationManager.AppSettings["OcpApimSubscriptionKey"].ToString());
                if (encryptedOTP != "")
                {
                    GST_Auth_Token auth = new GST_Auth_Token();
                    auth.action = "AUTHTOKEN";
                    auth.app_key = dtl.app_key;
                    auth.username = MerchantGSTUserName;
                    auth.otp = encryptedOTP;

                    var reqJson = JsonConvert.SerializeObject(auth);

                    string response = web.callHTTPWebRequestforGST(GST_API_URL + "taxpayerapi/v0.3/dev/authenticate", reqJson, "POST", headers);

                    Logging.LogInfo("RequestforAuthorizationToken Response: \r\n" + response);

                    var respJson = JsonConvert.DeserializeObject<dynamic>(response);

                    if (respJson["status_cd"] == "1")
                    {
                        GST_Auth_Resp Auth_Resp = JsonConvert.DeserializeObject<GST_Auth_Resp>(response);
                        baseResp.status = 0;
                        baseResp.message = "Authentication token generated successfully";
                        baseResp.data = Auth_Resp;
                    }
                    else
                    {
                        baseResp.status = 501;
                        baseResp.message = respJson["error"]["message"];
                        baseResp.data = "";
                    }
                }
                else
                {
                    baseResp.status = 501;
                    baseResp.message = "OTP failed to encrypt";
                    baseResp.data = "";
                }
            }
            else
            {
                baseResp.status = 501;
                baseResp.message = "Missing parameters";
                baseResp.data = "";
            }
            return GenericResponse(baseResp);

        }

        /// <summary>
        /// Refresh token can be used by GSP to extend access through Authorization code and allow for access to data
        /// </summary>
        /// <param name="dtl"></param>
        /// <returns></returns>
        [HttpPost]
        [Route("RequestforRefreshToken")]
        public HttpResponseMessage RequestforRefreshToken(GenericGSTReq dtl)
        {
            Logging.LogInfo("RequestforRefreshToken Request: \r\n" + JsonConvert.SerializeObject(dtl));
            getMerchantDetails(Convert.ToInt32(dtl.username));
            setHeaders();
            headers.Add("state-cd", MerchantStateID.Substring(0, 2));

            if (dtl.auth_token != "" || MerchantGSTUserName != "")
            {
                GST_Refresh_Token auth = new GST_Refresh_Token();
                auth.action = "REFRESHTOKEN";
                auth.app_key = encryption.generateAppKey();
                auth.username = MerchantGSTUserName;
                auth.auth_token = dtl.auth_token;

                var reqJson = JsonConvert.SerializeObject(auth);

                string response = web.callHTTPWebRequestforGST(GST_API_URL + "taxpayerapi/v0.3/dev/authenticate", reqJson, "POST", headers);

                Logging.LogInfo("RequestforAuthorizationToken Response: \r\n" + response);

                var respJson = JsonConvert.DeserializeObject<dynamic>(response);

                if (respJson["status_cd"] == "1")
                {
                    GST_Auth_Resp Auth_Resp = JsonConvert.DeserializeObject<GST_Auth_Resp>(response);
                    baseResp.status = 0;
                    baseResp.message = "Authentication token generated successfully";
                    baseResp.data = Auth_Resp;
                }
                else
                {
                    baseResp.status = 501;
                    baseResp.message = respJson["error"]["message"];
                    baseResp.data = "";
                }
            }
            else
            {
                baseResp.status = 501;
                baseResp.message = "Missing parameters";
                baseResp.data = "";
            }
            return GenericResponse(baseResp);

        }

        /// <summary>
        /// API is used to save entire GSTR1 invoices.
        /// </summary>
        /// <param name="dtl"></param>
        /// <returns></returns>
        [HttpPost]
        [Route("saveGSTR1")]
        public HttpResponseMessage saveGSTR1(GenericGSTReq dtl)
        {
            Logging.LogInfo("saveGSTR1 Request: \r\n" + JsonConvert.SerializeObject(dtl));

            getMerchantDetails(Convert.ToInt32(dtl.username));
            setHeaders();
            GSTR1SaveData data = JsonConvert.DeserializeObject<GSTR1SaveData>(dtl.payload.ToString());
            headers.Add("auth-token", dtl.auth_token);
            headers.Add("state-cd", MerchantStateID.Substring(0, 2));
            headers.Add("username", MerchantGSTUserName);
            headers.Add("gstin", MerchantStateID);
            headers.Add("ret_period", data.fp);
            data.gstin = MerchantStateID;
            dtl.payload = data;
            byte[] decryptedSek = encryption.decrypt(dtl.sek, ConfigurationManager.AppSettings["OcpApimSubscriptionKey"].ToString());

            if (dtl.sek != "" || MerchantGSTUserName != "" || dtl.auth_token != "")
            {
                string payload = JsonConvert.SerializeObject(dtl.payload);
                string encryptedPayload = encryption.Encrypt(payload, decryptedSek);
                string requestPayload = "{\"action\": \"RETSAVE\"," +
                 "\"data\": \"" + encryptedPayload + "\"," +
                 "\"hmac\": \"" + encryption.HMAC_Encrypt(payload, decryptedSek) + "\"" +
                 "}";

                string response = web.callHTTPWebRequestforGST(GST_API_URL + "taxpayerapi/v0.3/dev/returns/gstr1", requestPayload, "PUT", headers);

                Logging.LogInfo("saveGSTR1 Response: \r\n" + response);

                var respJson = JsonConvert.DeserializeObject<dynamic>(response);

                if (respJson["status_cd"] == "1")
                {
                    string finalJson = decryptResponse(respJson["rek"], respJson["data"], decryptedSek);
                    Logging.LogInfo("Summary GSTR1 decrypted json Response: " + finalJson);
                    baseResp.status = 0;
                    baseResp.message = "gstr1 saved successfully";
                    baseResp.data = JsonConvert.DeserializeObject(finalJson);
                }
                else
                {
                    baseResp.status = 501;
                    baseResp.message = respJson["error"]["message"];
                    baseResp.data = "";
                }
            }
            else
            {
                baseResp.status = 501;
                baseResp.message = "Missing parameters";
                baseResp.data = "";
            }
            return GenericResponse(baseResp);
        }

        #endregion       

    }
}
