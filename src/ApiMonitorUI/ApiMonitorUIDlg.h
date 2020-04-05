
// ApiMonitorUIDlg.h: 头文件
//

#pragma once
#include <thread>
#include <vector>
#include "ApiMonitor.h"

class Monitor;
class PipeController;

// CApiMonitorUIDlg 对话框
class CApiMonitorUIDlg : public CDialogEx
{
// 构造
public:
	CApiMonitorUIDlg(CWnd* pParent = nullptr);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_APIMONITORUI_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持

public:
    static CString ToCString(const std::string& str);
    static CString ToCString(long long i, bool hex = false);
    static std::wstring ToWString(const std::string & str);
    void UpdateModuleList(void* me);    // PipeController::ModuleEntry*
    void AppendApiCallLog(void* ai);    // PipeController::ApiLog*

    Monitor*                m_Monitor;
    PipeController*         m_Controller;
    std::vector<ApiLogItem> m_ApiLogs;

// 实现
protected:
	HICON m_hIcon;
    CEdit m_editFilePath;
    CTreeCtrl m_treeModuleList;
    CListCtrl m_listApiCalls;

    std::thread m_RunningMonitorThread;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
    afx_msg void OnBnClickedButton1();
    afx_msg LRESULT OnTreeListAddModule(WPARAM wParam, LPARAM lParam);
    afx_msg void OnTimer(UINT nIDEvent);
    afx_msg void OnSize(UINT nType, int cx, int cy);
};
