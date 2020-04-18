
// ApiMonitorUIDlg.h: 头文件
//

#pragma once
#include <mutex>
#include <set>
#include <thread>
#include <vector>
#include "ApiMonitor.h"
#include "ColumnTreeCtrl.h"
#include "config.h"

class Monitor;
class PipeController;

struct SetBreakConditionUI : public PipeDefine::msg::SetBreakCondition
{
    bool operator<(const SetBreakConditionUI& rhs) const
    {
        return this->func_addr < rhs.func_addr;
    }
};

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
    void UpdateModuleList(void* me);        // PipeController::ModuleEntry*
    void AppendApiCallLog(void* ai);        // PipeController::ApiLog*
    void CheckBreakCondition(void* ai);     // PipeController::ApiLog*

    bool IsModuleFunctionSelected();

    Monitor*                         m_Monitor;
    PipeController*                  m_Controller;
    std::vector<ApiLogItem>          m_ApiLogs;
    std::mutex                       m_LogLock;
    std::vector<ModuleInfoItem>      m_Modules;
    std::set<SetBreakConditionUI>    m_BreakPoints;     // SetBreakConditionUI 和 ApiLogItem 应整合到 ModuleInfoItem 里

// 实现
protected:
	HICON                       m_hIcon;
    CEdit                       m_editFilePath;
    CColumnTreeCtrl             m_treeModuleList;
    CListCtrl                   m_listApiCalls;

    std::thread                 m_RunningMonitorThread;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
    virtual void OnOK() {}
    virtual void OnCancel() {}

	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
    afx_msg void OnBnClickedButton1();
    afx_msg LRESULT OnTreeListAddModule(WPARAM wParam, LPARAM lParam);
    afx_msg void OnTimer(UINT nIDEvent);
    afx_msg void OnSize(UINT nType, int cx, int cy);
    afx_msg void OnBnClickedButtonExport();
    afx_msg void OnClose();
    afx_msg void OnFileExit();
    afx_msg void OnOptionConfig();
    afx_msg void OnNMRClickTreeModules(NMHDR *pNMHDR, LRESULT *pResult);
    afx_msg void OnSetbreakpointMeethittime();
    afx_msg void OnUpdateSetBreakPointMeetHitTime(CCmdUI *pCmdUI);
    afx_msg void OnSetbreakpointAlways();
    afx_msg void OnUpdateSetbreakpointAlways(CCmdUI *pCmdUI);
    afx_msg void OnSetBreakPointDelete();
};
