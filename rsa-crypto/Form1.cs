using System.Security.Cryptography;
using System.Text;

namespace rsa_crypto
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        private void Form1_Load(object sender, EventArgs e)
        {

        }

        private void button2_Click(object sender, EventArgs e)
        {
            if (textBox1.Text != "")
            {
                RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048);

                RSAParameters publicKey = rsa.ExportParameters(false);
                RSAParameters privateKey = rsa.ExportParameters(true);
                string data = textBox1.Text;
                byte[] signature = rsa.SignData(Encoding.UTF8.GetBytes(data), new SHA1CryptoServiceProvider());

                rsa_crypto rsa_Crypto = new rsa_crypto();
                rsa_Crypto.ExportRSAKeysAndDataToXml(privateKey, publicKey, data, signature, "rsa_data.xml");

                string signatureString = Convert.ToBase64String(signature);
                MessageBox.Show("Tạo thành công. Signature:\n" + signatureString + "\nSignature đã được copy vào clipboard.", "Thông báo", MessageBoxButtons.OK, MessageBoxIcon.Information);

                Clipboard.SetText(signatureString);
            }
        }

        private void button4_Click(object sender, EventArgs e)
        {
            if(textBox2.Text != "" && textBox5.Text != "")
            {

                rsa_crypto rsa_Crypto = new rsa_crypto();
                string signatureString = textBox5.Text;
                string dataToVerify = textBox2.Text;
                byte[] signatureBytes = Convert.FromBase64String(signatureString);
                bool isValid = rsa_Crypto.VerifyRSAHashForMultipleRoots("rsa_data.xml", dataToVerify, signatureBytes);
                if (isValid)
                {
                    MessageBox.Show("Chữ kí số hợp lệ!");
                }
                else
                {
                    MessageBox.Show("Chữ kí số không hợp lệ!");
                }

            }
        }

        private void button3_Click(object sender, EventArgs e)
        {
            Application.Exit();
        }
    }
}