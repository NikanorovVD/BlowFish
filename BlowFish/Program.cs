using System.Text;

namespace BlowFish
{
    internal class Program
    {
        static void Main(string[] args)
        {
            BlowFish b = new BlowFish("04B915BA43FEB5B7", encoding: Encoding.UTF8);
            string plainText = "This is an incredibly strong algorithm!!";
            string cipherText = b.Encrypt_CBC(plainText);
            Console.WriteLine(cipherText);
            plainText = b.Decrypt_CBC(cipherText);
            Console.WriteLine(plainText);
        }
    }
}
