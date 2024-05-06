using System.Text;

namespace BlowFish
{
    internal class Program
    {
        static void Main(string[] args)
        {
            BlowFish blowFish = new BlowFish("3491ABCD985AC310", encoding: Encoding.UTF8);
            string plainText = "This is an incredibly strong algorithm!!";
            string cipherText = blowFish.Encrypt(plainText);
            Console.WriteLine(cipherText);
            plainText = blowFish.Decrypt(cipherText);
            Console.WriteLine(plainText);
        }
    }
}
