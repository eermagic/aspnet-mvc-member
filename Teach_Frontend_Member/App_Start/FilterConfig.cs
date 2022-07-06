using System.Web;
using System.Web.Mvc;

namespace Teach_Frontend_Member
{
    public class FilterConfig
    {
        public static void RegisterGlobalFilters(GlobalFilterCollection filters)
        {
            filters.Add(new HandleErrorAttribute());
        }
    }
}
