#pragma once


// CSetBreakPointTimeDialog 对话框

class CSetBreakPointTimeDialog : public CDialogEx
{
	DECLARE_DYNAMIC(CSetBreakPointTimeDialog)

public:
	CSetBreakPointTimeDialog(CWnd* pParent = nullptr);   // 标准构造函数
	virtual ~CSetBreakPointTimeDialog();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_SET_BP_TIME };
#endif

    CString m_Times;

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
};
