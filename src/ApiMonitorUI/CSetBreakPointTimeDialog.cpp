// CSetBreakPointTimeDialog.cpp: 实现文件
//

#include "stdafx.h"
#include "ApiMonitorUI.h"
#include "CSetBreakPointTimeDialog.h"
#include "afxdialogex.h"


// CSetBreakPointTimeDialog 对话框

IMPLEMENT_DYNAMIC(CSetBreakPointTimeDialog, CDialogEx)

CSetBreakPointTimeDialog::CSetBreakPointTimeDialog(CWnd* pParent /*=nullptr*/)
    : CDialogEx(IDD_SET_BP_TIME, pParent)
{

}

CSetBreakPointTimeDialog::~CSetBreakPointTimeDialog()
{
}

void CSetBreakPointTimeDialog::DoDataExchange(CDataExchange* pDX)
{
    CDialogEx::DoDataExchange(pDX);
    DDX_CBString(pDX, IDC_EDIT1, m_Times);
}

BOOL CSetBreakPointTimeDialog::OnInitDialog()
{
    GetDlgItem(IDC_EDIT1)->SetFocus();
    return FALSE;
}


BEGIN_MESSAGE_MAP(CSetBreakPointTimeDialog, CDialogEx)
END_MESSAGE_MAP()


// CSetBreakPointTimeDialog 消息处理程序
