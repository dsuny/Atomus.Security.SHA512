using System;
using System.Security.Cryptography;
using System.Text;

namespace Atomus.Security
{
    /// <summary>
    /// SHA512 해시 알고리즘
    /// </summary>
    public class SHA512 : ISecureHashAlgorithm
    {
        string ISecureHashAlgorithm.ComputeHash(string value)
        {
            try
            {
                return ((ISecureHashAlgorithm)this).ComputeHash(value, Encoding.UTF8);
            }
            catch (AtomusException exception)
            {
                throw exception;
            }
            catch (Exception exception)
            {
                throw new AtomusException(exception);
            }
        }

        string ISecureHashAlgorithm.ComputeHash(string value, Encoding encoding)
        {
            try
            {
                if (encoding == null)
                    encoding = Encoding.UTF8;

                return encoding.GetString(((ISecureHashAlgorithm)this).ComputeHash(encoding.GetBytes(value)));
            }
            catch (AtomusException exception)
            {
                throw exception;
            }
            catch (Exception exception)
            {
                throw new AtomusException(exception);
            }
        }

        byte[] ISecureHashAlgorithm.ComputeHash(byte[] value)
        {
            Byte[] bytes;

            try
            {
                using (HashAlgorithm sHAManaged = new SHA512Managed())
                {
                    bytes = sHAManaged.ComputeHash(value);
                    sHAManaged.Clear();

                    return bytes;
                }
            }
            catch (AtomusException exception)
            {
                throw exception;
            }
            catch (Exception exception)
            {
                throw new AtomusException(exception);
            }
        }

        string ISecureHashAlgorithm.ComputeHashToBase64String(string value)
        {
            return Convert.ToBase64String(((ISecureHashAlgorithm)this).ComputeHash(Encoding.UTF8.GetBytes(value)));
        }

        string ISecureHashAlgorithm.ComputeHashToBase64String(string value, Encoding encoding)
        {
            if (encoding == null)
                encoding = Encoding.UTF8;

            return Convert.ToBase64String(((ISecureHashAlgorithm)this).ComputeHash(encoding.GetBytes(value)));
        }
    }
}
