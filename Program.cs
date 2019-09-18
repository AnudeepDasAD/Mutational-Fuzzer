using System;
using System.Net;
using System.IO;

namespace c_sharp_projs
{
    class Program
    {
        static void Main(string[] args)
        {
            string url = args[0]; //Getting the input, assumed to be a URL
            int index = url.IndexOf("?");

            //Remove any characters up to and including the '?' in order to start analysis
            //'?' indicates that the URL has ended and query parameters begin

            //& is the beginning of the new parameter
            //url.Remove(0, index+1) contains only the URL parameters (after the '?')
            string[] parms = url.Remove(0, index+1).Split('&');

            //Prints out each parameter
            foreach(string parm in parms)
                Console.WriteLine(parm);

            //Query parameters isolated, can begin fuzzing

            
            //Breaks apart the query part of the URL into individual parameters 
                //and replaces each of them, sequentially, with xss and sql tainted data,
                // tests the tainted data by sending requests and seeing the response
            foreach (string parm in parms) {

                //Bad queries
                string xssUrl = url.Replace(parm, "fd<xss>sa");
                string sqlUrl = url.Replace(parm, "fd'sa");

                Console.WriteLine(xssUrl);
                Console.WriteLine(sqlUrl);

                //Build HTTP web request and see if any errors come up
                    //A secure website should be able to sanitize the input and not process the bad requests

                HttpWebRequest request = (HttpWebRequest)WebRequest.Create(sqlUrl);
                request.Method = "GET";  //Making a GET request

                //Getting the response
                string sqlresp = string.Empty;
                using (StreamReader rdr = new StreamReader(request.GetResponse().GetResponseStream()))
                        sqlresp = rdr.ReadToEnd();
                
                //XSS
                string xssresp = string.Empty;
                request = (HttpWebRequest)WebRequest.Create(xssUrl);
                request.Method = "GET";

                using (StreamReader rdr = new StreamReader(request.GetResponse().GetResponseStream()))
                    xssresp = rdr.ReadToEnd();
                
                //unsanitized
                if (xssresp.Contains("<xss>"))
                //Replaced parm in the actual url, but value of parm still stored
                    Console.WriteLine("Possible XSS point found in parameter: " + parm);

                //Unsanitized
                if (sqlresp.Contains("error in your SQL syntax"))
                    Console.WriteLine("SQL injection found in parameter: "+ parm);
            }
        }
    }
}
