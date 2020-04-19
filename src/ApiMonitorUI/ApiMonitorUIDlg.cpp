
// ApiMonitorUIDlg.cpp: 实现文件
//

#include "stdafx.h"
#include <iomanip>
#include <sstream>
#include "ApiMonitorUI.h"
#include "ApiMonitorUIDlg.h"
#include "afxdialogex.h"
#include "ApiMonitor.h"
#include "CAddModuleFilterDlg.h"
#include "CSetBreakPointTimeDialog.h"
#include "uihelper.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

#define ID_REFRESH_API_CALL_LOG_TIMER 1
#define WM_TREE_ADD_MODULE WM_USER+100  

const int TreeCtrlColumnIndex_Module     = 0;
const int TreeCtrlColumnIndex_VA         = 1;
const int TreeCtrlColumnIndex_HookCount  = 2;
const int TreeCtrlColumnIndex_HitCount   = 3;
const int TreeCtrlColumnIndex_BreakPoint = 4;

const int ListApiColumnIndex_No          = 0;
const int ListApiColumnIndex_TID         = 1;
const int ListApiColumnIndex_RetAddr     = 2;
const int ListApiColumnIndex_Module      = 3;
const int ListApiColumnIndex_Name        = 4;
const int ListApiColumnIndex_Count       = 5;
const int ListApiColumnIndex_Arg0        = 6;
const int ListApiColumnIndex_Arg1        = 7;
const int ListApiColumnIndex_Arg2        = 8;


void Reply(const uint8_t *readData, uint32_t readDataSize, uint8_t *writeData, uint32_t *writeDataSize, const uint32_t maxWriteBuffer, void* userData);


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CApiMonitorUIDlg 对话框


CApiMonitorUIDlg::CApiMonitorUIDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_APIMONITORUI_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CApiMonitorUIDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
    DDX_Control(pDX, IDE_FILE_PATH, m_editFilePath);
    DDX_Control(pDX, IDC_TREE_MODULES, m_treeModuleList);
    DDX_Control(pDX, IDC_LIST_API_LOGS, m_listApiCalls);
}

void CApiMonitorUIDlg::UpdateModuleList(void* pv)
{
    SendMessage(WM_TREE_ADD_MODULE, (WPARAM)pv, 0);
}

void CApiMonitorUIDlg::AppendApiCallLog(void * pv)
{
    ApiLogItem* al = reinterpret_cast<ApiLogItem*>(pv);
    al->mApiNameW = ToWString(al->mApiName);
    al->mModuleNameW = ToWString(al->mModuleName);
    std::unique_lock<std::mutex> lk(m_LogLock);
    m_ApiLogs.push_back(*al);
}

void CApiMonitorUIDlg::CheckBreakCondition(void * pv)
{
    ApiLogItem* al = reinterpret_cast<ApiLogItem*>(pv);
}

BEGIN_MESSAGE_MAP(CApiMonitorUIDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
    ON_BN_CLICKED(IDC_BUTTON1, &CApiMonitorUIDlg::OnBnClickedButton1)
    ON_MESSAGE(WM_TREE_ADD_MODULE, &CApiMonitorUIDlg::OnTreeListAddModule)
    ON_WM_TIMER()
    ON_WM_SIZE()
    ON_BN_CLICKED(IDC_BUTTON_EXPORT, &CApiMonitorUIDlg::OnBnClickedButtonExport)
    ON_WM_CLOSE()
    ON_COMMAND(ID_FILE_EXIT, &CApiMonitorUIDlg::OnFileExit)
    ON_COMMAND(ID_OPTION_CONFIG, &CApiMonitorUIDlg::OnOptionConfig)
    ON_NOTIFY(NM_RCLICK, IDC_TREE_MODULES, &CApiMonitorUIDlg::OnNMRClickTreeModules)
    ON_COMMAND(ID_SETBREAKPOINT_MEETHITTIME, &CApiMonitorUIDlg::OnSetbreakpointMeethittime)
    ON_UPDATE_COMMAND_UI(ID_SETBREAKPOINT_MEETHITTIME, &CApiMonitorUIDlg::OnUpdateSetBreakPointMeetHitTime)
    ON_COMMAND(ID_SETBREAKPOINT_ALWAYS, &CApiMonitorUIDlg::OnSetbreakpointAlways)
    ON_UPDATE_COMMAND_UI(ID_SETBREAKPOINT_ALWAYS, &CApiMonitorUIDlg::OnUpdateSetbreakpointAlways)
    ON_COMMAND(ID_SETBREAKPOINT_DELETE, &CApiMonitorUIDlg::OnSetBreakPointDelete)
    ON_COMMAND(ID_SETBREAKPOINT_NEXTTIME, &CApiMonitorUIDlg::OnSetbreakpointNexttime)
END_MESSAGE_MAP()


// CApiMonitorUIDlg 消息处理程序

BOOL CApiMonitorUIDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

    m_treeModuleList.GetTreeCtrl().ModifyStyle(NULL, TVS_FULLROWSELECT | TVS_HASLINES | TVS_LINESATROOT | TVS_HASBUTTONS | TVS_CHECKBOXES);
    m_treeModuleList.InsertColumn(TreeCtrlColumnIndex_Module,       _T("Module"),       LVCFMT_LEFT, 200, -1);
    m_treeModuleList.InsertColumn(TreeCtrlColumnIndex_VA,           _T("VA"),           LVCFMT_LEFT, 100, -1);
    m_treeModuleList.InsertColumn(TreeCtrlColumnIndex_HookCount,    _T("Hook Count"),   LVCFMT_LEFT, 100, -1);
    m_treeModuleList.InsertColumn(TreeCtrlColumnIndex_HitCount,     _T("Hit Count"),    LVCFMT_LEFT, 100, -1);
    m_treeModuleList.InsertColumn(TreeCtrlColumnIndex_BreakPoint,   _T("Break Point"),  LVCFMT_LEFT, 100, -1);

    SetTimer(ID_REFRESH_API_CALL_LOG_TIMER, 1000, NULL);

    m_listApiCalls.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
    m_listApiCalls.InsertColumn(ListApiColumnIndex_No     , _T("No."),     LVCFMT_LEFT, 50,  -1);
    m_listApiCalls.InsertColumn(ListApiColumnIndex_TID    , _T("TID"),     LVCFMT_LEFT, 50,  -1);
    m_listApiCalls.InsertColumn(ListApiColumnIndex_RetAddr, _T("RetAddr"), LVCFMT_LEFT, 70,  -1);
    m_listApiCalls.InsertColumn(ListApiColumnIndex_Module , _T("Module"),  LVCFMT_LEFT, 120, -1);
    m_listApiCalls.InsertColumn(ListApiColumnIndex_Name   , _T("Name"),    LVCFMT_LEFT, 150, -1);
    m_listApiCalls.InsertColumn(ListApiColumnIndex_Count  , _T("Count"),   LVCFMT_LEFT, 50,  -1);
    m_listApiCalls.InsertColumn(ListApiColumnIndex_Arg0   , _T("Arg0"),    LVCFMT_LEFT, 70,  -1);
    m_listApiCalls.InsertColumn(ListApiColumnIndex_Arg1   , _T("Arg1"),    LVCFMT_LEFT, 70,  -1);
    m_listApiCalls.InsertColumn(ListApiColumnIndex_Arg2   , _T("Arg2"),    LVCFMT_LEFT, 70,  -1);

    m_listApiCalls.Invalidate();

    m_Controller = new PipeController();
    m_Controller->mMsgHandler = Reply;
    m_Controller->mUserData = this;

    m_Monitor = new Monitor();
    m_Monitor->SetPipeHandler(m_Controller);

    m_editFilePath.SetWindowText(L"C:\\Projects\\ApiMonitor\\bin\\Win32\\Release\\TestExe.exe");

    if (!DllFilterConfig::GetConfig()->LoadFromFile())
    {
        AfxMessageBox(_T("config not exist or invalid"));
    }

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CApiMonitorUIDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CApiMonitorUIDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CApiMonitorUIDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void Reply(const uint8_t *readData, uint32_t readDataSize, uint8_t *writeData, uint32_t *writeDataSize, const uint32_t maxWriteBuffer, void* userData)
{
    CApiMonitorUIDlg* dlg = (CApiMonitorUIDlg*)userData;
    PipeController* pc = (PipeController*)dlg->m_Controller;

    printf("data arrive. size=%d\n", readDataSize);
    if (readDataSize < sizeof(PipeDefine::PipeMsg) + sizeof(size_t))
    {
        // 过短消息
        printf("too short.");
        return;
    }

    *writeDataSize = 0;
    uint8_t* originalWriteData = writeData;
    PipeDefine::Message* msg = (PipeDefine::Message*)readData;
    while ((const uint8_t *)msg - readData < readDataSize)
    {
        bool isUnknown = false;
        switch (msg->type)
        {
        case PipeDefine::Pipe_C_Req_Inited: {
            PipeDefine::msg::Init m;
            std::vector<char, Allocator::allocator<char>> str(msg->Content, msg->Content + msg->ContentSize);
            m.Unserial(str);
            m.dummy += 1;
            str = m.Serial();
            PipeDefine::Message* msg2 = (PipeDefine::Message*)writeData;
            msg2->type = PipeDefine::Pipe_S_Ack_Inited;
            msg2->tid = msg->tid;
            msg2->ContentSize = str.size();
            memcpy_s(msg2->Content, maxWriteBuffer, str.data(), str.size());
            *writeDataSize += msg2->HeaderLength + msg2->ContentSize;
            break;
        }
        case PipeDefine::Pipe_C_Req_ModuleApiList: {
            PipeDefine::msg::ModuleApis m;
            std::vector<char, Allocator::allocator<char>> str(msg->Content, msg->Content + msg->ContentSize);
            m.Unserial(str);
            ModuleInfoItem me;
            me.mName = m.module_name;
            me.mPath = m.module_path;
            me.mBase = m.module_base;
            for (size_t i = 0; i < m.apis.size(); ++i)
            {
                ModuleInfoItem::ApiEntry ae;
                ae.mName = m.apis[i].name;
                ae.mVa = m.apis[i].va;
                ae.mIsForward = m.apis[i].forward_api;
                ae.mIsDataExport = m.apis[i].data_export;
                ae.mForwardto = m.apis[i].forwardto;
                ae.mBp.func_addr = ae.mVa;
                me.mApis.push_back(ae);
                //if (!_stricmp(m.module_name.c_str(), "kernel32.dll") && m.apis[i].name == "OutputDebugStringA")
                //    pc->outputdbgstr = m.apis[i].va;
            }
            pc->mModuleApis.push_back(me);
            dlg->UpdateModuleList(&me);

            if (!m.no_reply)
            {
                PipeDefine::msg::ApiFilter filter;
                filter.module_name = m.module_name;
                for (size_t i = 0; i < me.mApis.size(); ++i)
                {
                    PipeDefine::msg::ApiFilter::Api filter_api;
                    filter_api.func_addr        = me.mApis[i].mVa;
                    filter_api.filter           = me.mApis[i].mIsHook;        // 由 UI 更新
                    
                    filter_api.bc_always        = me.mApis[i].mBp.break_always;
                    filter_api.bc_next_time     = me.mApis[i].mBp.break_next_time;
                    filter_api.bc_call_from     = me.mApis[i].mBp.break_call_from;
                    filter_api.bc_invoke_time   = me.mApis[i].mBp.break_invoke_time;
                    filter_api.call_from        = me.mApis[i].mBp.call_from;
                    filter_api.func_addr        = me.mApis[i].mBp.func_addr;
                    filter_api.invoke_time      = me.mApis[i].mBp.invoke_time;

                    filter.apis.push_back(filter_api);
                }
                str = filter.Serial();
                PipeDefine::Message* msg2 = (PipeDefine::Message*)writeData;
                msg2->type = PipeDefine::Pipe_S_Ack_FilterApi;
                msg2->tid = msg->tid;
                msg2->ContentSize = str.size();
                memcpy_s(msg2->Content, maxWriteBuffer, str.data(), str.size());
                *writeDataSize += msg2->HeaderLength + msg2->ContentSize;
            }
            break;
        }
        case PipeDefine::Pipe_C_Req_ApiInvoked: {
            PipeDefine::msg::ApiInvoked m;
            std::vector<char, Allocator::allocator<char>> str(msg->Content, msg->Content + msg->ContentSize);
            m.Unserial(str);
            ApiLogItem al;
            al.mModuleName = m.module_name;
            al.mApiName = m.api_name;
            al.mCallFrom = m.call_from;
            al.mTimes = m.times;
            al.mTid = msg->tid;
            al.mRawArgs[0] = m.raw_args[0];
            al.mRawArgs[1] = m.raw_args[1];
            al.mRawArgs[2] = m.raw_args[2];
            dlg->AppendApiCallLog(&al);
            if (m.wait_reply)
            {
                dlg->CheckBreakCondition(&al);
                PipeDefine::Message* msg2 = (PipeDefine::Message*)writeData;
                msg2->type = PipeDefine::Pipe_S_Ack_ApiInvoked;
                msg2->tid = msg->tid;
                PipeDefine::msg::ApiInvokedReply rly;
                rly.secret = m.secret;
                str = rly.Serial();
                msg2->ContentSize = str.size();
                memcpy_s(msg2->Content, maxWriteBuffer, str.data(), str.size());
                *writeDataSize += msg2->HeaderLength + msg2->ContentSize;
                //TRACE("[%d] %s.%05d,seed=%d\n", al.mTid, al.mApiName.c_str(), al.mTimes, rly.dummy_id);
            }
            break;
        }
        default:
            printf("unknown message type.\n");
            throw "unknown message type.";
            break;
        }

        writeData = originalWriteData + (*writeDataSize);
        msg = (PipeDefine::Message*)((intptr_t)msg + PipeDefine::Message::HeaderLength + msg->ContentSize);
    }
    TRACE("Write: %d bytes\n", *writeDataSize);
}


void CApiMonitorUIDlg::OnBnClickedButton1()
{
    CString path;
    m_editFilePath.GetWindowText(path);
    if (m_RunningMonitorThread.joinable())
    {
        AfxMessageBox(_T("Already running"));
        return;
    }

    m_RunningMonitorThread = std::thread([this, path]() {
        return m_Monitor->LoadFile(path.GetString());
    });
}

LRESULT CApiMonitorUIDlg::OnTreeListAddModule(WPARAM wParam, LPARAM lParam)
{
    ModuleInfoItem* mii = (ModuleInfoItem*)wParam;

    // 配置中的 api 数量与实际数量相同时应用配置里的设置
    if (DllFilterConfig::GetConfig()->GetModuleApiCountInConfig(mii->mPath) == mii->mApis.size())
    {
        for (size_t i = 0; i < mii->mApis.size(); ++i)
        {
            auto s = DllFilterConfig::GetConfig()->GetApiHookStatus(mii->mPath, mii->mApis[i].mName);
            ASSERT(s == DllFilterConfig::kHook || s == DllFilterConfig::kIgnore);
            mii->mApis[i].mIsHook = (s == DllFilterConfig::kHook);
        }
    }
    else
    {
        CAddModuleFilterDlg dlg(mii, this);
        dlg.DoModal();
    }
    m_Modules.push_back(*mii);

    HTREEITEM hRoot = m_treeModuleList.GetTreeCtrl().GetRootItem();
    if (hRoot == NULL)
    {
        hRoot = m_treeModuleList.GetTreeCtrl().InsertItem(_T("Modules"));
        m_treeModuleList.GetTreeCtrl().Expand(hRoot, TVE_EXPAND);
    }

    HTREEITEM hMod = m_treeModuleList.GetTreeCtrl().InsertItem(ToCString(mii->mName), NULL, NULL, hRoot);
    m_treeModuleList.SetItemText(hMod, TreeCtrlColumnIndex_VA, ToCString(mii->mBase, true));
    int hookCount = 0;
    for (size_t i = 0; i < mii->mApis.size(); ++i)
    {
        std::string name = mii->mApis[i].mName;
        if (mii->mApis[i].mIsForward)
        {
            name += "(-> ";
            name += mii->mApis[i].mForwardto;
            name += ")";
        }
        HTREEITEM hApi = m_treeModuleList.GetTreeCtrl().InsertItem(ToCString(name), NULL, NULL, hMod);
        m_treeModuleList.SetItemText(hApi, TreeCtrlColumnIndex_VA, ToCString(mii->mApis[i].mVa, true));
        m_treeModuleList.SetItemText(hApi, TreeCtrlColumnIndex_BreakPoint, ToCString(mii->mApis[i].GetBpDescription()));
        m_treeModuleList.GetTreeCtrl().SetCheck(hApi, mii->mApis[i].mIsHook);
        hookCount += (int)mii->mApis[i].mIsHook;
    }
    m_treeModuleList.GetTreeCtrl().SetCheck(hMod, mii->mApis.size() == hookCount);
    m_treeModuleList.SetItemText(hMod, TreeCtrlColumnIndex_HookCount, ToCString(hookCount));
    m_treeModuleList.GetTreeCtrl().EnsureVisible(hMod);
    return 0;
}

void CApiMonitorUIDlg::OnTimer(UINT nIDEvent)
{
    if (nIDEvent != ID_REFRESH_API_CALL_LOG_TIMER)
        return;

    size_t totalCount = m_listApiCalls.GetItemCount();
    size_t count = m_ApiLogs.size();

    if (totalCount >= count)
        return;

    bool autoScroll = totalCount == 0 || m_listApiCalls.IsItemVisible(totalCount - 1);

    int idx = 0;
    {
        std::unique_lock<std::mutex> lk(m_LogLock);
        for (size_t i = totalCount; i < count; ++i)
        {
            m_ApiLogs[i].mIndex = i;

            CString index       = ToCString(m_ApiLogs[i].mIndex);
            CString tid         = ToCString(m_ApiLogs[i].mTid);
            CString call_from   = ToCString(m_ApiLogs[i].mCallFrom, true);
            CString times       = ToCString(m_ApiLogs[i].mTimes);
            CString arg0        = ToCString(m_ApiLogs[i].mRawArgs[0], true);
            CString arg1        = ToCString(m_ApiLogs[i].mRawArgs[1], true);
            CString arg2        = ToCString(m_ApiLogs[i].mRawArgs[2], true);

            idx = m_listApiCalls.InsertItem(i, index);
            m_listApiCalls.SetItem(idx, ListApiColumnIndex_TID    , LVIF_TEXT, tid, 0, 0, 0, 0);
            m_listApiCalls.SetItem(idx, ListApiColumnIndex_RetAddr, LVIF_TEXT, call_from, 0, 0, 0, 0);
            m_listApiCalls.SetItem(idx, ListApiColumnIndex_Module , LVIF_TEXT, m_ApiLogs[i].mModuleNameW.c_str(), 0, 0, 0, 0);
            m_listApiCalls.SetItem(idx, ListApiColumnIndex_Name   , LVIF_TEXT, m_ApiLogs[i].mApiNameW.c_str(), 0, 0, 0, 0);
            m_listApiCalls.SetItem(idx, ListApiColumnIndex_Count  , LVIF_TEXT, times, 0, 0, 0, 0);
            m_listApiCalls.SetItem(idx, ListApiColumnIndex_Arg0   , LVIF_TEXT, arg0, 0, 0, 0, 0);
            m_listApiCalls.SetItem(idx, ListApiColumnIndex_Arg1   , LVIF_TEXT, arg1, 0, 0, 0, 0);
            m_listApiCalls.SetItem(idx, ListApiColumnIndex_Arg2   , LVIF_TEXT, arg2, 0, 0, 0, 0);
        }
    }
    if (autoScroll)
        m_listApiCalls.EnsureVisible(idx, TRUE);
}

void CApiMonitorUIDlg::OnSize(UINT nType, int cx, int cy)
{
    const int BORDER = 10;

    RECT rc;
    rc.top = 50;
    rc.left = BORDER;
    rc.right = cx / 2 - BORDER / 2;
    rc.bottom = cy - BORDER;
    m_treeModuleList.SetWindowPos(NULL, rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top, SWP_NOZORDER);

    rc.top = 50;
    rc.left = cx / 2 + BORDER / 2;
    rc.right = cx - BORDER;
    rc.bottom = cy - BORDER;
    m_listApiCalls.SetWindowPos(NULL, rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top, SWP_NOZORDER);
}

typedef std::stringstream sstream_t;

void CApiMonitorUIDlg::OnBnClickedButtonExport()
{
    CString exePath;
    m_editFilePath.GetWindowText(exePath);
    WIN32_FIND_DATA wfd;
    HANDLE hFind = FindFirstFile(exePath, &wfd);
    if (hFind == NULL)
    {
        exePath = _T("noname");
    }
    else
    {
        exePath = wfd.cFileName;
        FindClose(hFind);
    }
    CFileDialog dlg(FALSE, _T("txt"), exePath + _T("_result"));
    if (IDOK != dlg.DoModal())
        return;

    CString savePath = dlg.GetPathName();

    HANDLE hSave = CreateFile(savePath, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
    if (hSave == INVALID_HANDLE_VALUE)
        return;

    DWORD R;
    std::vector<ModuleInfoItem> tmpModule = m_Modules;
    for (size_t i = 0; i < tmpModule.size(); ++i)
    {
        sstream_t ss;
        ss << "Module\n-------------------------------\nName: " << tmpModule[i].mName << ", Path: " << tmpModule[i].mPath << ", Base: "
           << std::hex << tmpModule[i].mBase << "\n";
        for (size_t k = 0; k < tmpModule[i].mApis.size(); ++k)
        {
            ss << "No." << std::setw(5) << std::setfill('0') << (k + 1) << " [" << (tmpModule[i].mApis[k].mIsHook ? "+" : "-") << "] " << tmpModule[i].mApis[k].mName;
            if (tmpModule[i].mApis[k].mIsForward)
                ss << "--> " << tmpModule[i].mApis[k].mForwardto;
            else
                ss << ", VA: " << tmpModule[i].mApis[k].mVa << ", DataExport: " << (tmpModule[i].mApis[k].mIsDataExport ? "Yes" : "No");
            ss << "\n";
        }
        ss << "\n";
        auto s = ss.str();
        WriteFile(hSave, s.c_str(), s.size(), &R, 0);
    }
    
    std::vector<ApiLogItem> tmpLog;
    {
        std::unique_lock<std::mutex> lk(m_LogLock);
        tmpLog = m_ApiLogs;
    }

    sstream_t ss;
    ss << "\n\nApi Call Logs\n-------------------------------\n";
    for (size_t i = 0; i < tmpLog.size(); ++i)
    {
        ss << "No." << std::setw(5) << std::setfill('0') << tmpLog[i].mIndex << " Tid: " << tmpLog[i].mTid << ", RetAddr: " << std::hex << tmpLog[i].mCallFrom
            << ", Module: " << tmpLog[i].mModuleName << " Name: " << tmpLog[i].mApiName << ", Count: " << tmpLog[i].mTimes;
        for (size_t k = 0; k < _countof(tmpLog[i].mRawArgs); ++k)
        {
            ss << ", Arg" << k << ": " << std::hex << tmpLog[i].mRawArgs[k];
        }
        ss << "\n";
    }
    auto s = ss.str();
    WriteFile(hSave, s.c_str(), s.size(), &R, 0);
    CloseHandle(hSave);
    AfxMessageBox(_T("Save Succees."), MB_ICONINFORMATION);
}


void CApiMonitorUIDlg::OnClose()
{
    CDialogEx::OnCancel();
}


void CApiMonitorUIDlg::OnFileExit()
{
    OnClose();
}


void CApiMonitorUIDlg::OnOptionConfig()
{
    ShellExecute(0, _T("open"), _T("notepad.exe"), DllFilterConfig::GetConfig()->GetConfigPath(), DllFilterConfig::GetConfig()->GetConfigDir(), SW_NORMAL);
}


void CApiMonitorUIDlg::OnNMRClickTreeModules(NMHDR *pNMHDR, LRESULT *pResult)
{
    CPoint point, clPos;
    GetCursorPos(&point);
    clPos = point;
    m_treeModuleList.ScreenToClient(&clPos);
    HTREEITEM hItem = m_treeModuleList.HitTest(clPos);
    if (hItem == NULL)
        return; 

    m_treeModuleList.GetTreeCtrl().SelectItem(hItem);
    CMenu menu;
    menu.LoadMenu(IDR_TREE_POP_MENU);
    CMenu *pPopup = menu.GetSubMenu(0);
    pPopup->TrackPopupMenu(TPM_LEFTALIGN | TPM_RIGHTBUTTON, point.x, point.y, this);
    *pResult = 0;
}

bool CApiMonitorUIDlg::IsModuleFunctionSelected()
{
    auto hItem = m_treeModuleList.GetTreeCtrl().GetSelectedItem();
    if (!hItem)
        return false;
    if (m_treeModuleList.GetTreeCtrl().ItemHasChildren(hItem))       // 模块不设断点
        return false;

    return true;
}

void CApiMonitorUIDlg::OnSetbreakpointMeethittime()
{
    if (!IsModuleFunctionSelected())
        return;

    CSetBreakPointTimeDialog dlg(this);
    if (IDOK != dlg.DoModal())
        return;

    int times = _wtoi(dlg.m_Times);
    if (times <= 0)
        return;

    auto hItem = m_treeModuleList.GetTreeCtrl().GetSelectedItem();
    if (!hItem)
        return;

    SetBreakConditionUI sbc;
    sbc.func_addr = ToInt(m_treeModuleList.GetItemText(hItem, 1), true);    // VA
    sbc.invoke_time = times;
    sbc.break_invoke_time = true;
    auto it = m_BreakPoints.find(sbc);
    m_BreakPoints.insert(it, sbc);

    m_treeModuleList.SetItemText(hItem, TreeCtrlColumnIndex_BreakPoint, CString(_T("times == ")) + dlg.m_Times);
}

void CApiMonitorUIDlg::OnSetbreakpointAlways()
{
    if (!IsModuleFunctionSelected())
        return;

    auto hItem = m_treeModuleList.GetTreeCtrl().GetSelectedItem();
    if (!hItem)
        return;

    SetBreakConditionUI sbc;
    sbc.func_addr = ToInt(m_treeModuleList.GetItemText(hItem, 1), true);    // VA
    sbc.break_always = true;
    auto it = m_BreakPoints.find(sbc);
    m_BreakPoints.insert(it, sbc);

    m_treeModuleList.SetItemText(hItem, TreeCtrlColumnIndex_BreakPoint, _T("Always"));
}

void CApiMonitorUIDlg::OnUpdateSetBreakPointMeetHitTime(CCmdUI *pCmdUI)
{
    pCmdUI->Enable(IsModuleFunctionSelected());
}

void CApiMonitorUIDlg::OnUpdateSetbreakpointAlways(CCmdUI *pCmdUI)
{
    pCmdUI->Enable(IsModuleFunctionSelected());
}

void CApiMonitorUIDlg::OnSetBreakPointDelete()
{
    if (!IsModuleFunctionSelected())
        return;

    auto hItem = m_treeModuleList.GetTreeCtrl().GetSelectedItem();
    if (!hItem)
        return;

    SetBreakConditionUI sbc;
    sbc.func_addr = ToInt(m_treeModuleList.GetItemText(hItem, 1), true);    // VA
    m_BreakPoints.erase(sbc);

    m_treeModuleList.SetItemText(hItem, TreeCtrlColumnIndex_BreakPoint, _T(""));
}


void CApiMonitorUIDlg::OnSetbreakpointNexttime()
{
    if (!IsModuleFunctionSelected())
        return;

    auto hItem = m_treeModuleList.GetTreeCtrl().GetSelectedItem();
    if (!hItem)
        return;

    SetBreakConditionUI sbc;
    sbc.func_addr = ToInt(m_treeModuleList.GetItemText(hItem, 1), true);    // VA
    sbc.break_next_time = true;
    auto it = m_BreakPoints.find(sbc);
    m_BreakPoints.insert(it, sbc);

    m_treeModuleList.SetItemText(hItem, TreeCtrlColumnIndex_BreakPoint, _T("Next Time"));
}
