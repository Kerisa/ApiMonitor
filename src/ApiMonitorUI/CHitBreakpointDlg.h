#pragma once


// CHitBreakpointDlg 对话框
struct SetBreakConditionUI;
class CHitBreakpointDlg : public CDialogEx
{
	DECLARE_DYNAMIC(CHitBreakpointDlg)

public:
	CHitBreakpointDlg(SetBreakConditionUI* bc, CWnd* pParent = nullptr);   // 标准构造函数
	virtual ~CHitBreakpointDlg();

    CString m_ModuleName;
    CString m_FunctionName;
    CString m_VA;
    CString m_Cond;

    SetBreakConditionUI* m_bc{ nullptr };

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_BREAKPOINT_HIT };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持
    virtual BOOL OnInitDialog();

	DECLARE_MESSAGE_MAP()
};
