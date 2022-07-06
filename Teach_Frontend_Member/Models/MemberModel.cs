using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace Teach_Frontend_Member.Models
{
    public class MemberModel
    {
        /// <summary>
        /// 註冊參數
        /// </summary>
        public class DoRegisterIn
        {
            public string UserID { get; set; }
            public string UserPwd { get; set; }
            public string UserName { get; set; }
            public string UserEmail { get; set; }
        }

        /// <summary>
        /// 註冊回傳
        /// </summary>
        public class DoRegisterOut
        {
            public string ErrMsg { get; set; }
            public string ResultMsg { get; set; }  
        }

        /// <summary>
        /// 登入參數
        /// </summary>
        public class DoLoginIn
        {
            public string UserID { get; set; }
            public string UserPwd { get; set; }
            public string KeepLogin { get; set; }
        }

        /// <summary>
        /// 登入回傳
        /// </summary>
        public class DoLoginOut
        {
            public string ErrMsg { get; set; }
            public string ResultMsg { get; set; }
        }

        /// <summary>
        /// 取得個人資料回傳
        /// </summary>
        public class GetUserProfileOut
        {
            public string ErrMsg { get; set; }
            public string UserID { get; set; }
            public string UserName { get; set; }
            public string UserEmail { get; set; }
        }

        /// <summary>
        /// 修改個人資料參數
        /// </summary>
        public class DoEditProfileIn
        {
            public string UserName { get; set; }
            public string UserEmail { get; set; }
        }

        /// <summary>
        /// 修改個人資料回傳
        /// </summary>
        public class DoEditProfileOut
        {
            public string ErrMsg { get; set; }
            public string ResultMsg { get; set; }
        }

        /// <summary>
        /// 修改密碼參數
        /// </summary>
        public class DoEditPwdIn
        {
            public string NewUserPwd { get; set; }
            public string CheckUserPwd { get; set; }
        }

        /// <summary>
        /// 修改密碼回傳
        /// </summary>
        public class DoEditPwdOut
        {
            public string ErrMsg { get; set; }
            public string ResultMsg { get; set; }
        }

        /// <summary>
        /// [寄送驗證碼]參數
        /// </summary>
        public class SendMailTokenIn
        {
            public string UserID { get; set; }
        }

        /// <summary>
        /// [寄送驗證碼]回傳
        /// </summary>
        public class SendMailTokenOut
        {
            public string ErrMsg { get; set; }
            public string ResultMsg { get; set; }
        }

        /// <summary>
        /// [重設密碼]參數
        /// </summary>
        public class DoResetPwdIn
        {
            public string NewUserPwd { get; set; }
            public string CheckUserPwd { get; set; }
        }

        /// <summary>
        /// [重設密碼]回傳
        /// </summary>
        public class DoResetPwdOut
        {
            public string ErrMsg { get; set; }
            public string ResultMsg { get; set; }
        }
        
    }
}