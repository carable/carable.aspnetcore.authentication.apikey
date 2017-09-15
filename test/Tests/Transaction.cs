using System.Collections.Generic;
using System.Net.Http;
using System.Xml.Linq;

namespace Tests
{
    public class Transaction
    {
        public HttpRequestMessage Request { get; set; }
        public HttpResponseMessage Response { get; set; }
        public string ResponseText { get; internal set; }
        public XElement ResponseElement { get; set; }


    }
}