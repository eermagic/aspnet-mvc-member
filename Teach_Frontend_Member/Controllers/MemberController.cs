using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data;
using System.Data.Common;
using System.Data.SqlClient;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using System.Web.Mvc;
using static Teach_Frontend_Member.Models.MemberModel;

namespace Teach_Frontend_Member.Controllers
{
    public class MemberController : Controller
    {
        #region 頁面載入動作
        // GET: 註冊頁面
        public ActionResult Register()
        {
            return View();
        }

        // GET: 登入頁面
        public ActionResult Login()
        {
            if (Request.Cookies["UserKeepLogin"] != null)
            {
                if (!string.IsNullOrEmpty(Request.Cookies["UserKeepLogin"].Value))
                {
                    string ckUserKeepLoginVerify = Request.Cookies["UserKeepLogin"].Value;

                    // 取出帳號密碼
                    string UserID = ckUserKeepLoginVerify.Split('|')[0];
                    string UserPwd = ckUserKeepLoginVerify.Split('|')[1];

                    // 資料庫連線
                    string connStr = System.Web.Configuration.WebConfigurationManager.ConnectionStrings["ConnDB"].ConnectionString;
                    SqlConnection conn = new SqlConnection();
                    conn.ConnectionString = connStr;
                    conn.Open();

                    // 檢查帳號、密碼是否正確
                    string sql = "select * from Member where UserID = @UserID and UserPwd = @UserPwd";
                    SqlCommand cmd = new SqlCommand();
                    cmd.CommandText = sql;
                    cmd.Connection = conn;

                    // 使用參數化填值
                    cmd.Parameters.AddWithValue("@UserID", UserID);
                    cmd.Parameters.AddWithValue("@UserPwd", UserPwd);

                    // 執行資料庫查詢動作
                    SqlDataAdapter adpt = new SqlDataAdapter();
                    adpt.SelectCommand = cmd;
                    DataSet ds = new DataSet();
                    adpt.Fill(ds);

                    if (ds.Tables[0].Rows.Count > 0)
                    {
                        // 有查詢到資料，表示帳號密碼正確

                        // 將登入帳號記錄在 Session 內
                        Session["UserID"] = UserID;

                        //給前端的資訊
                        ViewData["UserKeepLogin"] = "Y";

                        // 繼續延長 Cookie 時間
                        HttpCookie ckUserKeepLogin = new HttpCookie("UserKeepLogin"); //Cookie 名稱
                        ckUserKeepLogin.Value = UserID + "|" + UserPwd;//Cookie 值
                        ckUserKeepLogin.Expires = DateTime.Now.AddDays(7); //Cookie 有效期限
                        ckUserKeepLogin.HttpOnly = true; //防止 XSS 攻擊
                        Response.Cookies.Add(ckUserKeepLogin);
                    }
                }
            }

            return View();
        }

        // GET: 修改個人資料頁面
        public ActionResult EditProfile()
        {
            return View();
        }

        // GET: 忘記密碼頁面
        public ActionResult ForgetPwd()
        {
            return View();
        }

        // GET: 重設密碼頁面
        public ActionResult ResetPwd(string verify)
        {
            // 由信件連結回來會帶參數 verify

            if (verify == "")
            {
                ViewData["ErrorMsg"] = "缺少驗證碼";
                return View();
            }

            // 取得系統自定密鑰，在 Web.config 設定
            string SecretKey = ConfigurationManager.AppSettings["SecretKey"];

            try
            {
                // 使用 3DES 解密驗證碼
                TripleDESCryptoServiceProvider DES = new TripleDESCryptoServiceProvider();
                MD5 md5 = new MD5CryptoServiceProvider();
                byte[] buf = Encoding.UTF8.GetBytes(SecretKey);
                byte[] md5result = md5.ComputeHash(buf);
                string md5Key = BitConverter.ToString(md5result).Replace("-", "").ToLower().Substring(0, 24);
                DES.Key = UTF8Encoding.UTF8.GetBytes(md5Key);
                DES.Mode = CipherMode.ECB;
                DES.Padding = System.Security.Cryptography.PaddingMode.PKCS7;
                ICryptoTransform DESDecrypt = DES.CreateDecryptor();
                byte[] Buffer = Convert.FromBase64String(verify);
                string deCode = UTF8Encoding.UTF8.GetString(DESDecrypt.TransformFinalBlock(Buffer, 0, Buffer.Length));

                verify = deCode; //解密後還原資料
            }
            catch (Exception ex)
            {
                ViewData["ErrorMsg"] = "驗證碼錯誤";
                return View();
            }

            // 取出帳號
            string UserID = verify.Split('|')[0];

            // 取得重設時間
            string ResetTime = verify.Split('|')[1];

            // 檢查時間是否超過 30 分鐘
            DateTime dResetTime = Convert.ToDateTime(ResetTime);
            TimeSpan TS = new System.TimeSpan(DateTime.Now.Ticks - dResetTime.Ticks);
            double diff = Convert.ToDouble(TS.TotalMinutes);
            if (diff > 30)
            {
                ViewData["ErrorMsg"] = "超過驗證碼有效時間，請重寄驗證碼";
                return View();
            }

            // 驗證碼檢查成功，加入 Session
            Session["ResetPwdUserId"] = UserID;

            return View();
        }

        #endregion

        #region 查詢相關
        /// <summary>
        /// 執行登入
        /// </summary>
        /// <param name="inModel"></param>
        /// <returns></returns>
        public ActionResult DoLogin(DoLoginIn inModel)
        {
            DoLoginOut outModel = new DoLoginOut();

            // 檢查輸入資料
            if (string.IsNullOrEmpty(inModel.UserID) || string.IsNullOrEmpty(inModel.UserPwd))
            {
                outModel.ErrMsg = "請輸入資料";
            }
            else
            {
                SqlConnection conn = null;

                try
                {
                    // 資料庫連線
                    string connStr = System.Web.Configuration.WebConfigurationManager.ConnectionStrings["ConnDB"].ConnectionString;
                    conn = new SqlConnection();
                    conn.ConnectionString = connStr;
                    conn.Open();

                    // 將密碼轉為 SHA256 雜湊運算(不可逆)
                    string salt = inModel.UserID.Substring(0, 1).ToLower(); //使用帳號前一碼當作密碼鹽
                    SHA256 sha256 = SHA256.Create();
                    byte[] bytes = Encoding.UTF8.GetBytes(salt + inModel.UserPwd); //將密碼鹽及原密碼組合
                    byte[] hash = sha256.ComputeHash(bytes);
                    StringBuilder result = new StringBuilder();
                    for (int i = 0; i < hash.Length; i++)
                    {
                        result.Append(hash[i].ToString("X2"));
                    }
                    string CheckPwd = result.ToString(); // 雜湊運算後密碼

                    // 檢查帳號、密碼是否正確
                    string sql = "select * from Member where UserID = @UserID and UserPwd = @UserPwd";
                    SqlCommand cmd = new SqlCommand();
                    cmd.CommandText = sql;
                    cmd.Connection = conn;

                    // 使用參數化填值
                    cmd.Parameters.AddWithValue("@UserID", inModel.UserID);
                    cmd.Parameters.AddWithValue("@UserPwd", CheckPwd); // 雜湊運算後密碼

                    // 執行資料庫查詢動作
                    SqlDataAdapter adpt = new SqlDataAdapter();
                    adpt.SelectCommand = cmd;
                    DataSet ds = new DataSet();
                    adpt.Fill(ds);

                    if (ds.Tables[0].Rows.Count > 0)
                    {
                        // 有查詢到資料，表示帳號密碼正確

                        // 將登入帳號記錄在 Session 內
                        Session["UserID"] = inModel.UserID;

                        outModel.ResultMsg = "登入成功";

                        // 檢查是否保持登入
                        if (inModel.KeepLogin == "true")
                        {
                            HttpCookie ckUserKeepLogin = new HttpCookie("UserKeepLogin"); //Cookie 名稱
                            ckUserKeepLogin.Value = inModel.UserID + "|" + CheckPwd; //Cookie 值
                            ckUserKeepLogin.Expires = DateTime.Now.AddDays(7); //Cookie 有效期限
                            ckUserKeepLogin.HttpOnly = true; //防止 XSS 攻擊
                            Response.Cookies.Add(ckUserKeepLogin);
                        }
                    }
                    else
                    {
                        // 查無資料，帳號或密碼錯誤
                        outModel.ErrMsg = "帳號或密碼錯誤";
                    }
                }
                catch (Exception ex)
                {
                    throw ex;
                }
                finally
                {
                    if (conn != null)
                    {
                        //關閉資料庫連線
                        conn.Close();
                        conn.Dispose();
                    }
                }

            }

            // 輸出json
            ContentResult resultJson = new ContentResult();
            resultJson.ContentType = "application/json";
            resultJson.Content = JsonConvert.SerializeObject(outModel); ;
            return resultJson;
        }

        /// <summary>
        /// 取得個人資料
        /// </summary>
        /// <returns></returns>
        public ActionResult GetUserProfile()
        {
            GetUserProfileOut outModel = new GetUserProfileOut();

            // 檢查會員 Session 是否存在
            if (Session["UserID"] == null || Session["UserID"].ToString() == "")
            {
                outModel.ErrMsg = "無會員登入記錄";
                return Json(outModel);
            }

            // 取得連線字串
            string connStr = System.Web.Configuration.WebConfigurationManager.ConnectionStrings["ConnDB"].ConnectionString;

            // 當程式碼離開 using 區塊時，會自動關閉連接
            using (SqlConnection conn = new SqlConnection(connStr))
            {
                // 資料庫連線
                conn.Open();

                // 取得會員資料
                string sql = "select * from Member where UserID = @UserID";
                SqlCommand cmd = new SqlCommand();
                cmd.CommandText = sql;
                cmd.Connection = conn;

                // 使用參數化填值
                cmd.Parameters.AddWithValue("@UserID", Session["UserID"]);

                // 執行資料庫查詢動作
                SqlDataAdapter adpt = new SqlDataAdapter();
                adpt.SelectCommand = cmd;
                DataSet ds = new DataSet();
                adpt.Fill(ds);
                DataTable dt = ds.Tables[0];

                if (dt.Rows.Count > 0)
                {
                    // 將資料回傳給前端
                    outModel.UserID = dt.Rows[0]["UserID"].ToString();
                    outModel.UserName = dt.Rows[0]["UserName"].ToString();
                    outModel.UserEmail = dt.Rows[0]["UserEmail"].ToString();
                }
                else
                {
                    outModel.ErrMsg = "查無會員資料";
                }
            }

            // 回傳 Json 給前端
            return Json(outModel);
        }

        /// <summary>
        /// 寄送驗證碼
        /// </summary>
        /// <returns></returns>
        [ValidateAntiForgeryToken]
        public ActionResult SendMailToken(SendMailTokenIn inModel)
        {
            SendMailTokenOut outModel = new SendMailTokenOut();

            // 檢查輸入來源
            if (string.IsNullOrEmpty(inModel.UserID))
            {
                outModel.ErrMsg = "請輸入帳號";
                return Json(outModel);
            }

            // 檢查資料庫是否有這個帳號

            // 取得資料庫連線字串
            string connStr = System.Web.Configuration.WebConfigurationManager.ConnectionStrings["ConnDB"].ConnectionString;

            // 當程式碼離開 using 區塊時，會自動關閉連接
            using (SqlConnection conn = new SqlConnection(connStr))
            {
                // 資料庫連線
                conn.Open();

                // 取得會員資料
                string sql = "select * from Member where UserID = @UserID";
                SqlCommand cmd = new SqlCommand();
                cmd.CommandText = sql;
                cmd.Connection = conn;

                // 使用參數化填值
                cmd.Parameters.AddWithValue("@UserID", inModel.UserID);

                // 執行資料庫查詢動作
                SqlDataAdapter adpt = new SqlDataAdapter();
                adpt.SelectCommand = cmd;
                DataSet ds = new DataSet();
                adpt.Fill(ds);
                DataTable dt = ds.Tables[0];

                if (dt.Rows.Count > 0)
                {
                    // 取出會員信箱
                    string UserEmail = dt.Rows[0]["UserEmail"].ToString();

                    // 取得系統自定密鑰，在 Web.config 設定
                    string SecretKey = ConfigurationManager.AppSettings["SecretKey"];

                    // 產生帳號+時間驗證碼
                    string sVerify = inModel.UserID + "|" + DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss");

                    // 將驗證碼使用 3DES 加密
                    TripleDESCryptoServiceProvider DES = new TripleDESCryptoServiceProvider();
                    MD5 md5 = new MD5CryptoServiceProvider();
                    byte[] buf = Encoding.UTF8.GetBytes(SecretKey);
                    byte[] result = md5.ComputeHash(buf);
                    string md5Key = BitConverter.ToString(result).Replace("-", "").ToLower().Substring(0, 24);
                    DES.Key = UTF8Encoding.UTF8.GetBytes(md5Key);
                    DES.Mode = CipherMode.ECB;
                    ICryptoTransform DESEncrypt = DES.CreateEncryptor();
                    byte[] Buffer = UTF8Encoding.UTF8.GetBytes(sVerify);
                    sVerify = Convert.ToBase64String(DESEncrypt.TransformFinalBlock(Buffer, 0, Buffer.Length)); // 3DES 加密後驗證碼

                    // 將加密後密碼使用網址編碼處理
                    sVerify = HttpUtility.UrlEncode(sVerify);

                    // 網站網址
                    string webPath = Request.Url.Scheme + "://" + Request.Url.Authority + Url.Content("~/");

                    // 從信件連結回到重設密碼頁面
                    string receivePage = "Member/ResetPwd";

                    // 信件內容範本
                    string mailContent = "請點擊以下連結，返回網站重新設定密碼，逾期 30 分鐘後，此連結將會失效。<br><br>";
                    mailContent = mailContent + "<a href='" + webPath + receivePage + "?verify=" + sVerify + "'  target='_blank'>點此連結</a>";

                    // 信件主題
                    string mailSubject = "[測試] 重設密碼申請信";

                    // Google 發信帳號密碼
                    string GoogleMailUserID = ConfigurationManager.AppSettings["GoogleMailUserID"];
                    string GoogleMailUserPwd = ConfigurationManager.AppSettings["GoogleMailUserPwd"];

                    // 使用 Google Mail Server 發信
                    string SmtpServer = "smtp.gmail.com";
                    int SmtpPort = 587;
                    MailMessage mms = new MailMessage();
                    mms.From = new MailAddress(GoogleMailUserID);
                    mms.Subject = mailSubject;
                    mms.Body = mailContent;
                    mms.IsBodyHtml = true;
                    mms.SubjectEncoding = Encoding.UTF8;
                    mms.To.Add(new MailAddress(UserEmail));
                    using (SmtpClient client = new SmtpClient(SmtpServer, SmtpPort))
                    {
                        client.EnableSsl = true;
                        client.Credentials = new NetworkCredential(GoogleMailUserID, GoogleMailUserPwd);//寄信帳密 
                        client.Send(mms); //寄出信件
                    }
                    outModel.ResultMsg = "請於 30 分鐘內至你的信箱點擊連結重新設定密碼，逾期將無效";
                }
                else
                {
                    outModel.ErrMsg = "查無此帳號";
                }
            }

            // 回傳 Json 給前端
            return Json(outModel);
        }
        #endregion

        #region 新增相關
        /// <summary>
        /// 執行註冊
        /// </summary>
        /// <param name="inModel"></param>
        /// <returns></returns>
        public ActionResult DoRegister(DoRegisterIn inModel)
        {
            DoRegisterOut outModel = new DoRegisterOut();

            if (string.IsNullOrEmpty(inModel.UserID) || string.IsNullOrEmpty(inModel.UserPwd) || string.IsNullOrEmpty(inModel.UserName) || string.IsNullOrEmpty(inModel.UserEmail))
            {
                outModel.ErrMsg = "請輸入資料";
            }
            else
            {
                SqlConnection conn = null;
                try
                {
                    // 資料庫連線
                    string connStr = System.Web.Configuration.WebConfigurationManager.ConnectionStrings["ConnDB"].ConnectionString;
                    conn = new SqlConnection();
                    conn.ConnectionString = connStr;
                    conn.Open();

                    // 檢查帳號是否存在
                    string sql = "select * from Member where UserID = @UserID";
                    SqlCommand cmd = new SqlCommand();
                    cmd.CommandText = sql;
                    cmd.Connection = conn;

                    // 使用參數化填值
                    cmd.Parameters.AddWithValue("@UserID", inModel.UserID);

                    // 執行資料庫查詢動作
                    DbDataAdapter adpt = new SqlDataAdapter();
                    adpt.SelectCommand = cmd;
                    DataSet ds = new DataSet();
                    adpt.Fill(ds);

                    if (ds.Tables[0].Rows.Count > 0)
                    {
                        outModel.ErrMsg = "此登入帳號已存在";
                    }
                    else
                    {
                        // 將密碼使用 SHA256 雜湊運算(不可逆)
                        string salt = inModel.UserID.Substring(0, 1).ToLower(); //使用帳號前一碼當作密碼鹽
                        SHA256 sha256 = SHA256.Create();
                        byte[] bytes = Encoding.UTF8.GetBytes(salt + inModel.UserPwd); //將密碼鹽及原密碼組合
                        byte[] hash = sha256.ComputeHash(bytes);
                        StringBuilder result = new StringBuilder();
                        for (int i = 0; i < hash.Length; i++)
                        {
                            result.Append(hash[i].ToString("X2"));
                        }
                        string NewPwd = result.ToString(); // 雜湊運算後密碼

                        // 註冊資料新增至資料庫
                        sql = @"INSERT INTO Member (UserID,UserPwd,UserName,UserEmail) VALUES (@UserID, @UserPwd, @UserName, @UserEmail)";
                        cmd = new SqlCommand();
                        cmd.Connection = conn;
                        cmd.CommandText = sql;

                        // 使用參數化填值
                        cmd.Parameters.AddWithValue("@UserID", inModel.UserID);
                        cmd.Parameters.AddWithValue("@UserPwd", NewPwd); // 雜湊運算後密碼
                        cmd.Parameters.AddWithValue("@UserName", inModel.UserName);
                        cmd.Parameters.AddWithValue("@UserEmail", inModel.UserEmail);

                        // 執行資料庫更新動作
                        cmd.ExecuteNonQuery();

                        outModel.ResultMsg = "註冊完成";
                    }
                }
                catch (Exception ex)
                {
                    throw ex;
                }
                finally
                {
                    if (conn != null)
                    {
                        //關閉資料庫連線
                        conn.Close();
                        conn.Dispose();
                    }
                }
            }

            // 輸出json
            ContentResult resultJson = new ContentResult();
            resultJson.ContentType = "application/json";
            resultJson.Content = JsonConvert.SerializeObject(outModel); ;
            return resultJson;
        }
        #endregion

        #region 修改相關
        /// <summary>
        /// 修改個人資料
        /// </summary>
        /// <param name="inModel"></param>
        /// <returns></returns>
        [ValidateAntiForgeryToken]
        public ActionResult DoEditProfile(DoEditProfileIn inModel)
        {
            DoEditProfileOut outModel = new DoEditProfileOut();

            // 檢查個人資料是否有輸入
            if (string.IsNullOrEmpty(inModel.UserName) || string.IsNullOrEmpty(inModel.UserEmail))
            {
                outModel.ErrMsg = "請輸入資料";
                return Json(outModel);
            }

            // 檢查會員 Session 是否存在
            if (Session["UserID"] == null || Session["UserID"].ToString() == "")
            {
                outModel.ErrMsg = "無會員登入記錄";
                return Json(outModel);
            }

            // 取得連線字串
            string connStr = System.Web.Configuration.WebConfigurationManager.ConnectionStrings["ConnDB"].ConnectionString;

            // 當程式碼離開 using 區塊時，會自動關閉連接
            using (SqlConnection conn = new SqlConnection(connStr))
            {
                // 資料庫連線
                conn.Open();

                // 修改個人資料至資料庫
                string sql = @"UPDATE Member SET UserName = @UserName, UserEmail = @UserEmail WHERE UserID = @UserID";
                SqlCommand cmd = new SqlCommand();
                cmd.Connection = conn;
                cmd.CommandText = sql;

                // 使用參數化填值
                cmd.Parameters.AddWithValue("@UserID", Session["UserID"]);
                cmd.Parameters.AddWithValue("@UserName", inModel.UserName);
                cmd.Parameters.AddWithValue("@UserEmail", inModel.UserEmail);

                // 執行資料庫更新動作
                int Ret = cmd.ExecuteNonQuery();

                if (Ret > 0)
                {
                    outModel.ResultMsg = "修改個人資料完成";
                }
                else
                {
                    outModel.ErrMsg = "無異動資料";
                }
            }

            // 回傳 Json 給前端
            return Json(outModel);
        }

        /// <summary>
        /// 修改密碼
        /// </summary>
        /// <param name="inModel"></param>
        /// <returns></returns>
        [ValidateAntiForgeryToken]
        public ActionResult DoEditPwd(DoEditPwdIn inModel)
        {
            DoEditPwdOut outModel = new DoEditPwdOut();

            // 檢查是否有輸入密碼
            if (string.IsNullOrEmpty(inModel.NewUserPwd))
            {
                outModel.ErrMsg = "請輸入修改密碼";
                return Json(outModel);
            }
            if (string.IsNullOrEmpty(inModel.CheckUserPwd))
            {
                outModel.ErrMsg = "請輸入確認新密碼";
                return Json(outModel);
            }
            if (inModel.NewUserPwd != inModel.CheckUserPwd)
            {
                outModel.ErrMsg = "新密碼與確認新密碼不相同";
                return Json(outModel);
            }

            // 檢查會員 Session 是否存在
            if (Session["UserID"] == null || Session["UserID"].ToString() == "")
            {
                outModel.ErrMsg = "無會員登入記錄";
                return Json(outModel);
            }

            // 將新密碼使用 SHA256 雜湊運算(不可逆)
            string salt = Session["UserID"].ToString().Substring(0, 1).ToLower(); //使用帳號前一碼當作密碼鹽
            SHA256 sha256 = SHA256.Create();
            byte[] bytes = Encoding.UTF8.GetBytes(salt + inModel.NewUserPwd); //將密碼鹽及新密碼組合
            byte[] hash = sha256.ComputeHash(bytes);
            StringBuilder result = new StringBuilder();
            for (int i = 0; i < hash.Length; i++)
            {
                result.Append(hash[i].ToString("X2"));
            }
            string NewPwd = result.ToString(); // 雜湊運算後密碼

            // 取得連線字串
            string connStr = System.Web.Configuration.WebConfigurationManager.ConnectionStrings["ConnDB"].ConnectionString;

            // 當程式碼離開 using 區塊時，會自動關閉連接
            using (SqlConnection conn = new SqlConnection(connStr))
            {
                // 資料庫連線
                conn.Open();

                // 修改個人資料至資料庫
                string sql = @"UPDATE Member SET UserPwd = @UserPwd WHERE UserID = @UserID";
                SqlCommand cmd = new SqlCommand();
                cmd.Connection = conn;
                cmd.CommandText = sql;

                // 使用參數化填值
                cmd.Parameters.AddWithValue("@UserID", Session["UserID"]);
                cmd.Parameters.AddWithValue("@UserPwd", NewPwd);

                // 執行資料庫更新動作
                int Ret = cmd.ExecuteNonQuery();

                if (Ret > 0)
                {
                    outModel.ResultMsg = "修改密碼完成";
                }
                else
                {
                    outModel.ErrMsg = "無異動資料";
                }
            }

            // 回傳 Json 給前端
            return Json(outModel);
        }

        /// <summary>
        /// 重設密碼
        /// </summary>
        /// <param name="inModel"></param>
        /// <returns></returns>
        [ValidateAntiForgeryToken]
        public ActionResult DoResetPwd(DoResetPwdIn inModel)
        {
            DoResetPwdOut outModel = new DoResetPwdOut();

            // 檢查是否有輸入密碼
            if (string.IsNullOrEmpty(inModel.NewUserPwd))
            {
                outModel.ErrMsg = "請輸入新密碼";
                return Json(outModel);
            }
            if (string.IsNullOrEmpty(inModel.CheckUserPwd))
            {
                outModel.ErrMsg = "請輸入確認新密碼";
                return Json(outModel);
            }
            if (inModel.NewUserPwd != inModel.CheckUserPwd)
            {
                outModel.ErrMsg = "新密碼與確認新密碼不相同";
                return Json(outModel);
            }

            // 檢查帳號 Session 是否存在
            if (Session["ResetPwdUserId"] == null || Session["ResetPwdUserId"].ToString() == "")
            {
                outModel.ErrMsg = "無修改帳號";
                return Json(outModel);
            }

            // 將新密碼使用 SHA256 雜湊運算(不可逆)
            string salt = Session["ResetPwdUserId"].ToString().Substring(0, 1).ToLower(); //使用帳號前一碼當作密碼鹽
            SHA256 sha256 = SHA256.Create();
            byte[] bytes = Encoding.UTF8.GetBytes(salt + inModel.NewUserPwd); //將密碼鹽及新密碼組合
            byte[] hash = sha256.ComputeHash(bytes);
            StringBuilder result = new StringBuilder();
            for (int i = 0; i < hash.Length; i++)
            {
                result.Append(hash[i].ToString("X2"));
            }
            string NewPwd = result.ToString(); // 雜湊運算後密碼

            // 取得連線字串
            string connStr = System.Web.Configuration.WebConfigurationManager.ConnectionStrings["ConnDB"].ConnectionString;

            // 當程式碼離開 using 區塊時，會自動關閉連接
            using (SqlConnection conn = new SqlConnection(connStr))
            {
                // 資料庫連線
                conn.Open();

                // 修改個人資料至資料庫
                string sql = @"UPDATE Member SET UserPwd = @UserPwd WHERE UserID = @UserID";
                SqlCommand cmd = new SqlCommand();
                cmd.Connection = conn;
                cmd.CommandText = sql;

                // 使用參數化填值
                cmd.Parameters.AddWithValue("@UserID", Session["ResetPwdUserId"]);
                cmd.Parameters.AddWithValue("@UserPwd", NewPwd);

                // 執行資料庫更新動作
                int Ret = cmd.ExecuteNonQuery();

                if (Ret > 0)
                {
                    outModel.ResultMsg = "重設密碼完成";
                }
                else
                {
                    outModel.ErrMsg = "無異動資料";
                }
            }

            // 回傳 Json 給前端
            return Json(outModel);
        }
        #endregion

        #region 刪除相關
        #endregion

        #region 事件相關
        #endregion

    }
}