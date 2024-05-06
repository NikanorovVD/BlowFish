using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BlowFish
{
    partial class BlowFish
    {
        private byte wordByte0(uint w)
        {
            return (byte)(w / 256 / 256 / 256 % 256);
        }

        private byte wordByte1(uint w)
        {
            return (byte)(w / 256 / 256 % 256);
        }

        private byte wordByte2(uint w)
        {
            return (byte)(w / 256 % 256);
        }
        private byte wordByte3(uint w)
        {
            return (byte)(w % 256);
        }
    }
}
