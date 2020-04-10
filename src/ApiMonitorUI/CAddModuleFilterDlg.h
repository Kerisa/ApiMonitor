#pragma once

struct ModuleInfoItem;

// CAddModuleFilterDlg 对话框

class CAddModuleFilterDlg : public CDialogEx
{
	DECLARE_DYNAMIC(CAddModuleFilterDlg)

public:
	CAddModuleFilterDlg(ModuleInfoItem* info, CWnd* pParent = nullptr);   // 标准构造函数
	virtual ~CAddModuleFilterDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ADD_MODULE_FILTER };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

    virtual BOOL OnInitDialog();
    DECLARE_MESSAGE_MAP()

protected:
    HICON           m_hIcon;
    CEdit           m_editName;
    CEdit           m_editPath;
    CEdit           m_editBase;
    CListCtrl       m_listModuleApis;
    CButton         m_checkAll;
    CButton         m_checkSaveToConfig;

    ModuleInfoItem* mModuleInfoItem{ nullptr };


public:
    afx_msg void OnPaint();
    afx_msg HCURSOR OnQueryDragIcon();
    virtual void OnOK();
    virtual void OnCancel();
    afx_msg void OnBnClickedCheckAll();
};
