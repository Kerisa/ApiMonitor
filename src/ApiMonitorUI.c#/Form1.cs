using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace ApiMonitorUI
{
    public partial class ApiMonitor : Form
    {
        public ApiMonitor()
        {
            InitializeComponent();
        }

        private void 文件FToolStripMenuItem_Click(object sender, EventArgs e)
        {

        }

        private void buttonRun_Click(object sender, EventArgs e)
        {
            Program.LoadFile(textBoxFilePath.Text);
        }

        private void textBoxFilePath_TextChanged(object sender, EventArgs e)
        {

        }
    }
}
