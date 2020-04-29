// CHitBreakpointDlg.cpp: 实现文件
//

#include "stdafx.h"
#include "ApiMonitorUI.h"
#include "CHitBreakpointDlg.h"
#include "afxdialogex.h"
#include "ApiMonitor.h"
#include "uihelper.h"

// CHitBreakpointDlg 对话框

IMPLEMENT_DYNAMIC(CHitBreakpointDlg, CDialogEx)

CHitBreakpointDlg::CHitBreakpointDlg(SetBreakConditionUI* bc, CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_BREAKPOINT_HIT, pParent)
{
    m_bc = bc;
}

CHitBreakpointDlg::~CHitBreakpointDlg()
{
}

void CHitBreakpointDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
    DDX_Text(pDX, IDC_MODULE, m_ModuleName);
    DDX_Text(pDX, IDC_FUNCNAME, m_FunctionName);
    DDX_Text(pDX, IDC_VA, m_VA);
    DDX_Text(pDX, IDC_COND, m_Cond);
}

BOOL CHitBreakpointDlg::OnInitDialog()
{
    CDialogEx::OnInitDialog();

    m_ModuleName   = ToCString(m_bc->mBelongApi->mBelongModule->mName);
    m_FunctionName = ToCString(m_bc->mBelongApi->mName);
    m_VA           = ToCString(m_bc->func_addr, true);
    switch (m_bc->flags)
    {
    case PipeDefine::msg::SetBreakCondition::FLAG_BC_ALWAYS:
        m_Cond = _T("Always Break");
        break;
    case PipeDefine::msg::SetBreakCondition::FLAG_BC_NEXT_TIME:
        m_Cond = _T("One-Time Break");
        break;
    case PipeDefine::msg::SetBreakCondition::FLAG_BC_CALL_FROM:
        m_Cond = CString(_T("Call From = ")) + ToCString(m_bc->call_from, true);
        break;
    case PipeDefine::msg::SetBreakCondition::FLAG_BC_INVOKE_TIME:
        m_Cond = CString(_T("Hit Time = ")) + ToCString(m_bc->invoke_time);
        break;
    default:
        m_Cond = _T("???");
        break;
    }
    UpdateData(FALSE);
    return TRUE;
}


BEGIN_MESSAGE_MAP(CHitBreakpointDlg, CDialogEx)
END_MESSAGE_MAP()


// CHitBreakpointDlg 消息处理程序
