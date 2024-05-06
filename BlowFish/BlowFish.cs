using System.Security.Cryptography;
using System.Text;

namespace BlowFish
{
    partial class BlowFish
    {
        RNGCryptoServiceProvider randomSource;
        Encoding encoding;

        //SBLOCKS
        private uint[] bf_s0;
        private uint[] bf_s1;
        private uint[] bf_s2;
        private uint[] bf_s3;

        private uint[] bf_P;

        //KEY
        private byte[] key;

        //HALF-BLOCKS
        private uint xl_par;
        private uint xr_par;

        private byte[] InitVector;
        private bool IVSet;

        //COMPATIBILITY WITH javascript CRYPTO LIBRARY
        private bool nonStandardMethod;

        public BlowFish(string hexKey, Encoding encoding)
        {
            this.encoding = encoding;
            randomSource = new RNGCryptoServiceProvider();
            SetupKey(HexToByte(hexKey));
        }



        /// <summary>
        /// Шифрует текст
        /// </summary>
        /// <param name="pt">Plaintext data to encrypt</param>
        /// <returns>Ciphertext with IV appended to front</returns>
        public string Encrypt_CBC(string pt)
        {
            if (!IVSet)
                SetRandomIV();
            return ByteToHex(InitVector) + ByteToHex(Encrypt_CBC(encoding.GetBytes(pt)));
        }

        /// <summary>
        /// Дешифрует текст
        /// </summary>
        /// <param name="ct">Ciphertext with IV appended to front</param>
        /// <returns>Plaintext</returns>
        public string Decrypt_CBC(string ct)
        {
            IV = HexToByte(ct.Substring(0, 16));
            return encoding.GetString(Decrypt_CBC(HexToByte(ct.Substring(16)))).Replace("\0", "");
        }

        /// <summary>
        /// Decrypts a byte array in CBC mode.
        /// IV must be created and saved manually.
        /// </summary>
        /// <param name="ct">Ciphertext data to decrypt</param>
        /// <returns>Plaintext</returns>
        public byte[] Decrypt_CBC(byte[] ct)
        {
            return Crypt_CBC(ct, true);
        }

        /// <summary>
        /// Encrypts a byte array in CBC mode.
        /// IV must be created and saved manually.
        /// </summary>
        /// <param name="pt">Plaintext data to encrypt</param>
        /// <returns>Ciphertext</returns>
        public byte[] Encrypt_CBC(byte[] pt)
        {
            return Crypt_CBC(pt, false);
        }

        /// <summary>
        /// Initialization vector for CBC mode.
        /// </summary>
        public byte[] IV
        {
            get { return InitVector; }
            set
            {
                if (value.Length == 8)
                {
                    InitVector = value;
                    IVSet = true;
                }
                else
                {
                    throw new Exception("Invalid IV size.");
                }
            }
        }

        /// <summary>
        /// Creates and sets a random initialization vector.
        /// </summary>
        /// <returns>The random IV</returns>
        public byte[] SetRandomIV()
        {
            InitVector = new byte[8];
            randomSource.GetBytes(InitVector);
            IVSet = true;
            return InitVector;
        }


        /// <summary>
        /// Sets up the S-blocks and the key
        /// </summary>
        /// <param name="cipherKey">Block cipher key (1-448 bits)</param>
        private void SetupKey(byte[] cipherKey)
        {
            bf_P = SetupP();
            //set up the S blocks
            bf_s0 = SetupS0();
            bf_s1 = SetupS1();
            bf_s2 = SetupS2();
            bf_s3 = SetupS3();

            key = new byte[cipherKey.Length]; // 448 bits
            if (cipherKey.Length > 56)
            {
                throw new Exception("Key too long. 56 bytes required.");
            }

            Buffer.BlockCopy(cipherKey, 0, key, 0, cipherKey.Length);
            int j = 0;
            for (int i = 0; i < 18; i++)
            {
                uint d = (uint)(((key[j % cipherKey.Length] * 256 + key[(j + 1) % cipherKey.Length]) * 256 + key[(j + 2) % cipherKey.Length]) * 256 + key[(j + 3) % cipherKey.Length]);
                bf_P[i] ^= d;
                j = (j + 4) % cipherKey.Length;
            }

            xl_par = 0;
            xr_par = 0;
            for (int i = 0; i < 18; i += 2)
            {
                encipher();
                bf_P[i] = xl_par;
                bf_P[i + 1] = xr_par;
            }

            for (int i = 0; i < 256; i += 2)
            {
                encipher();
                bf_s0[i] = xl_par;
                bf_s0[i + 1] = xr_par;
            }
            for (int i = 0; i < 256; i += 2)
            {
                encipher();
                bf_s1[i] = xl_par;
                bf_s1[i + 1] = xr_par;
            }
            for (int i = 0; i < 256; i += 2)
            {
                encipher();
                bf_s2[i] = xl_par;
                bf_s2[i + 1] = xr_par;
            }
            for (int i = 0; i < 256; i += 2)
            {
                encipher();
                bf_s3[i] = xl_par;
                bf_s3[i + 1] = xr_par;
            }
        }

        /// <summary>
        /// Encrypts or decrypts data in CBC mode
        /// </summary>
        /// <param name="text">plain/ciphertext</param>
        /// <param name="decrypt">true to decrypt, false to encrypt</param>
        /// <returns>(En/De)crypted data</returns>
        private byte[] Crypt_CBC(byte[] text, bool decrypt)
        {
            if (!IVSet)
            {
                throw new Exception("IV not set.");
            }
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

        /// <summary>
        /// XoR encrypts two 8 bit blocks
        /// </summary>
        /// <param name="block">8 bit block 1</param>
        /// <param name="iv">8 bit block 2</param>
        private void XorBlock(ref byte[] block, byte[] iv)
        {
            for (int i = 0; i < block.Length; i++)
            {
                block[i] ^= iv[i];
            }
        }

        /// <summary>
        /// Encrypts a 64 bit block
        /// </summary>
        /// <param name="block">The 64 bit block to encrypt</param>
        private void BlockEncrypt(ref byte[] block)
        {
            SetBlock(block);
            encipher();
            GetBlock(ref block);
        }

        /// <summary>
        /// Decrypts a 64 bit block
        /// </summary>
        /// <param name="block">The 64 bit block to decrypt</param>
        private void BlockDecrypt(ref byte[] block)
        {
            SetBlock(block);
            decipher();
            GetBlock(ref block);
        }

        /// <summary>
        /// Splits the block into the two uint values
        /// </summary>
        /// <param name="block">the 64 bit block to setup</param>
        private void SetBlock(byte[] block)
        {
            byte[] block1 = new byte[4];
            byte[] block2 = new byte[4];
            Buffer.BlockCopy(block, 0, block1, 0, 4);
            Buffer.BlockCopy(block, 4, block2, 0, 4);
            //split the block
            if (nonStandardMethod)
            {
                xr_par = BitConverter.ToUInt32(block1, 0);
                xl_par = BitConverter.ToUInt32(block2, 0);
            }
            else
            {
                //ToUInt32 requires the bytes in reverse order
                Array.Reverse(block1);
                Array.Reverse(block2);
                xl_par = BitConverter.ToUInt32(block1, 0);
                xr_par = BitConverter.ToUInt32(block2, 0);
            }
        }

        /// <summary>
        /// Converts the two uint values into a 64 bit block
        /// </summary>
        /// <param name="block">64 bit buffer to receive the block</param>
        private void GetBlock(ref byte[] block)
        {
            byte[] block1 = new byte[4];
            byte[] block2 = new byte[4];
            if (nonStandardMethod)
            {
                block1 = BitConverter.GetBytes(xr_par);
                block2 = BitConverter.GetBytes(xl_par);
            }
            else
            {
                block1 = BitConverter.GetBytes(xl_par);
                block2 = BitConverter.GetBytes(xr_par);

                //GetBytes returns the bytes in reverse order
                Array.Reverse(block1);
                Array.Reverse(block2);
            }
            //join the block
            Buffer.BlockCopy(block1, 0, block, 0, 4);
            Buffer.BlockCopy(block2, 0, block, 4, 4);
        }

        /// <summary>
        /// Runs the blowfish algorithm (standard 16 rounds)
        /// </summary>
        private void encipher()
        {
            xl_par ^= bf_P[0];
            for (uint i = 0; i < 16; i += 2)
            {
                xr_par = round(xr_par, xl_par, i + 1);
                xl_par = round(xl_par, xr_par, i + 2);
            }
            xr_par = xr_par ^ bf_P[17];

            //swap the blocks
            uint swap = xl_par;
            xl_par = xr_par;
            xr_par = swap;
        }

        /// <summary>
        /// Runs the blowfish algorithm in reverse (standard 16 rounds)
        /// </summary>
        private void decipher()
        {
            xl_par ^= bf_P[17];
            for (uint i = 16; i > 0; i -= 2)
            {
                xr_par = round(xr_par, xl_par, i);
                xl_par = round(xl_par, xr_par, i - 1);
            }
            xr_par = xr_par ^ bf_P[0];

            //swap the blocks
            (xl_par, xr_par) = (xr_par, xl_par);
        }

        /// <summary>
        /// one round of the blowfish algorithm
        /// </summary>
        /// <param name="a">See spec</param>
        /// <param name="b">See spec</param>
        /// <param name="n">See spec</param>
        /// <returns></returns>
        private uint round(uint a, uint b, uint n)
        {
            uint x1 = (bf_s0[wordByte0(b)] + bf_s1[wordByte1(b)]) ^ bf_s2[wordByte2(b)];
            uint x2 = x1 + bf_s3[this.wordByte3(b)];
            uint x3 = x2 ^ bf_P[n];
            return x3 ^ a;
        }
    }
}
