namespace SteamKit2.Util
{
   /// <summary>
   /// 
   /// </summary>
   public static class Adler32
    {
        private const uint BASE = 65521;
        private const int NMAX = 5552;


        /// <summary>
        /// 
        /// </summary>
        /// <param name="buffer"></param>
        /// <returns></returns>
        public static uint ComputeHash(byte[] buffer)
        {
            int offset = 0;
            int len = buffer.Length;

            uint adler = 0;


            uint sum2 = (adler >> 16) & 0xffff;
            adler &= 0xffff;
            uint n;


            if (len == 1)
            {
                adler += buffer[0];
                if (adler >= BASE)
                    adler -= BASE;
                sum2 += adler;
                if (sum2 >= BASE)
                    sum2 -= BASE;
                return adler | (sum2 << 16);
            }

            if (buffer.Length == 0)
                return 1;

            /* in case short lengths are provided, keep it somewhat fast */
            if (len < 16)
            {

                while (len-- > 0)
                {
                    adler += buffer[offset++];
                    sum2 += adler;
                }
                if (adler >= BASE)
                    adler -= BASE;
                sum2 %= BASE;            /* only added so many BASE's */
                return adler | (sum2 << 16);
            }

            /* do length NMAX blocks -- requires just one modulo operation */
            while (len >= NMAX)
            {
                len -= NMAX;
                n = NMAX / 16;
                while (n-- > 0)
                {
                    DO16(buffer, ref offset, ref adler, ref sum2);          /* 16 sums unrolled */
                }
                adler %= BASE;
                sum2 %= BASE;
            }

            if (len > 0)
            {                  /* avoid modulos if none remaining */
                while (len >= 16)
                {
                    len -= 16;
                    DO16(buffer, ref offset, ref adler, ref sum2);          /* 16 sums unrolled */
                }
                while (len-- > 0)
                {
                    adler += buffer[offset++];
                    sum2 += adler;
                }
                adler %= BASE;
                sum2 %= BASE;
            }


            return (adler | (sum2 << 16));
        }

        private static void DO1(byte[] buffer, ref int offset, ref uint adler, ref uint sum2)
        {

            adler += (buffer)[offset++];
            sum2 += adler;
        }


        private static  void DO2(byte[] buffer, ref int offset, ref uint adler, ref uint sum2)
        {

            DO1(buffer, ref offset, ref adler, ref sum2);
            DO1(buffer, ref offset, ref adler, ref sum2);
        }


        private static void DO4(byte[] buffer, ref int offset, ref uint adler, ref uint sum2)
        {
            DO2(buffer, ref offset, ref adler, ref sum2);
            DO2(buffer, ref offset, ref adler, ref sum2);

        }
        private static  void DO8(byte[] buffer, ref int offset, ref uint adler, ref uint sum2)
        {
            DO4(buffer, ref offset, ref adler, ref sum2);
            DO4(buffer, ref offset, ref adler, ref sum2);
        }
        private static void DO16(byte[] buffer, ref int offset, ref uint adler, ref uint sum2)
        {
            DO8(buffer, ref offset, ref adler, ref sum2);
            DO8(buffer, ref offset, ref adler, ref sum2);
        }

    }
}