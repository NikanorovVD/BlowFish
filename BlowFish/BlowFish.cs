using System.Security.Cryptography;
using System.Text;

namespace BlowFish
{
    partial class BlowFish
    {
        RNGCryptoServiceProvider randomSource;
        Encoding encoding;

        //Матрицы подстановки
        private uint[] s0;
        private uint[] s1;
        private uint[] s2;
        private uint[] s3;

        //раундовые ключи
        private uint[] P;

        //КЛЮЧ
        private byte[] key;

        //блоки
        private uint xl_par;
        private uint xr_par;

        private byte[] InitVector;


        public BlowFish(string hexKey, Encoding encoding)
        {
            this.encoding = encoding;
            randomSource = new RNGCryptoServiceProvider();
            SetupKey(HexToByte(hexKey));
        }



        // Зашифровать текст
        public string Encrypt(string pt)
        {
            SetRandomIV();
            return ByteToHex(InitVector) + ByteToHex(Encrypt(encoding.GetBytes(pt)));
        }

        // Зашифровать байты
        public byte[] Encrypt(byte[] pt)
        {
            return Crypt(pt, false);
        }

        // Дешифровать текст
        public string Decrypt(string ct)
        {
            IV = HexToByte(ct.Substring(0, 16));
            return encoding.GetString(Decrypt(HexToByte(ct.Substring(16)))).Replace("\0", "");
        }

        // Дешифровать байты
        public byte[] Decrypt(byte[] ct)
        {
            return Crypt(ct, true);
        }



        // IV - InitVector - 
        public byte[] IV
        {
            get { return InitVector; }
            set
            {
                if (value.Length == 8)
                {
                    InitVector = value;
                }
                else
                {
                    throw new Exception("Invalid IV size.");
                }
            }
        }

        // Устанавливает случайный InitVector
        public byte[] SetRandomIV()
        {
            InitVector = new byte[8];
            randomSource.GetBytes(InitVector);
            return InitVector;
        }


        // Устанавливает раундовые ключи и матрицы подстановки
        private void SetupKey(byte[] key)
        {
            P = SetupP();
            //set up the S blocks
            s0 = SetupS0();
            s1 = SetupS1();
            s2 = SetupS2();
            s3 = SetupS3();

            this.key = new byte[key.Length]; // 448 bits
            if (key.Length > 56)
            {
                throw new Exception("Key too long. 56 bytes required.");
            }

            Buffer.BlockCopy(key, 0, this.key, 0, key.Length);
            int j = 0;
            for (int i = 0; i < 18; i++)
            {
                uint d = (uint)(((this.key[j % key.Length] * 256 + this.key[(j + 1) % key.Length]) * 256 + this.key[(j + 2) % key.Length]) * 256 + this.key[(j + 3) % key.Length]);
                P[i] ^= d;
                j = (j + 4) % key.Length;
            }

            xl_par = 0;
            xr_par = 0;
            for (int i = 0; i < 18; i += 2)
            {
                Encrypt();
                P[i] = xl_par;
                P[i + 1] = xr_par;
            }

            for (int i = 0; i < 256; i += 2)
            {
                Encrypt();
                s0[i] = xl_par;
                s0[i + 1] = xr_par;
            }
            for (int i = 0; i < 256; i += 2)
            {
                Encrypt();
                s1[i] = xl_par;
                s1[i + 1] = xr_par;
            }
            for (int i = 0; i < 256; i += 2)
            {
                Encrypt();
                s2[i] = xl_par;
                s2[i + 1] = xr_par;
            }
            for (int i = 0; i < 256; i += 2)
            {
                Encrypt();
                s3[i] = xl_par;
                s3[i + 1] = xr_par;
            }
        }

        // Шифрует или дешифрует данные по блокам
        private byte[] Crypt(byte[] text, bool decrypt)
        {
            int paddedLen = (text.Length % 8 == 0 ? text.Length : text.Length + 8 - (text.Length % 8));
            byte[] plainText = new byte[paddedLen];
            Buffer.BlockCopy(text, 0, plainText, 0, text.Length);
            byte[] block = new byte[8];
            byte[] preblock = new byte[8];
            byte[] iv = new byte[8];
            Buffer.BlockCopy(InitVector, 0, iv, 0, 8);
            if (!decrypt)
            {
                for (int i = 0; i < plainText.Length; i += 8)
                {
                    Buffer.BlockCopy(plainText, i, block, 0, 8);
                    XorBlock(ref block, iv);
                    BlockEncrypt(ref block);
                    Buffer.BlockCopy(block, 0, iv, 0, 8);
                    Buffer.BlockCopy(block, 0, plainText, i, 8);
                }
            }
            else
            {
                for (int i = 0; i < plainText.Length; i += 8)
                {
                    Buffer.BlockCopy(plainText, i, block, 0, 8);

                    Buffer.BlockCopy(block, 0, preblock, 0, 8);
                    BlockDecrypt(ref block);
                    XorBlock(ref block, iv);
                    Buffer.BlockCopy(preblock, 0, iv, 0, 8);

                    Buffer.BlockCopy(block, 0, plainText, i, 8);
                }
            }
            return plainText;
        }

        // XOR между двумя блоками
        private void XorBlock(ref byte[] block, byte[] iv)
        {
            for (int i = 0; i < block.Length; i++)
            {
                block[i] ^= iv[i];
            }
        }

        // Шифрует один блок
        private void BlockEncrypt(ref byte[] block)
        {
            SetBlock(block);
            Encrypt();
            GetBlock(ref block);
        }

        // Дешифрует один блок
        private void BlockDecrypt(ref byte[] block)
        {
            SetBlock(block);
            Dencrypt();
            GetBlock(ref block);
        }

        // Разделяет один блок(64) на два uint'a(32)
        private void SetBlock(byte[] block)
        {
            byte[] block1 = new byte[4];
            byte[] block2 = new byte[4];

            Buffer.BlockCopy(block, 0, block1, 0, 4);
            Buffer.BlockCopy(block, 4, block2, 0, 4);

            Array.Reverse(block1);
            Array.Reverse(block2);

            xl_par = BitConverter.ToUInt32(block1, 0);
            xr_par = BitConverter.ToUInt32(block2, 0);
        }

        // Соединяет два uint'a(32) в один блок(64)
        private void GetBlock(ref byte[] block)
        {
            byte[] block1 = new byte[4];
            byte[] block2 = new byte[4];

            block1 = BitConverter.GetBytes(xl_par);
            block2 = BitConverter.GetBytes(xr_par);

            Array.Reverse(block1);
            Array.Reverse(block2);

            Buffer.BlockCopy(block1, 0, block, 0, 4);
            Buffer.BlockCopy(block2, 0, block, 4, 4);
        }

        // Шифрование по сети Фейстеля
        private void Encrypt()
        {
            xl_par ^= P[0];
            for (uint i = 0; i < 16; i += 2)
            {
                xr_par = Round(xr_par, xl_par, i + 1);
                xl_par = Round(xl_par, xr_par, i + 2);
            }
            xr_par = xr_par ^ P[17];
            (xl_par, xr_par) = (xr_par, xl_par);
        }

        // Дешифрование по сети Фейстеля
        private void Dencrypt()
        {
            xl_par ^= P[17];
            for (uint i = 16; i > 0; i -= 2)
            {
                xr_par = Round(xr_par, xl_par, i);
                xl_par = Round(xl_par, xr_par, i - 1);
            }
            xr_par = xr_par ^ P[0];
            (xl_par, xr_par) = (xr_par, xl_par);
        }

        // "Раунд" алгоритма BlowFish
        private uint Round(uint a, uint b, uint n)
        {
            return ((((s0[wordByte0(b)] + s1[wordByte1(b)]) ^ s2[wordByte2(b)]) + s3[wordByte3(b)]) ^ P[n]) ^ a;
        }
    }
}
