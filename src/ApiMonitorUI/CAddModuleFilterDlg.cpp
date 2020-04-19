// CAddModuleFilterDlg.cpp: 实现文件
//

#include "stdafx.h"
#include "ApiMonitorUI.h"
#include "CAddModuleFilterDlg.h"
#include "afxdialogex.h"
#include "ApiMonitor.h"
#include "uihelper.h"
#include "config.h"
#include "CSetBreakPointTimeDialog.h"

// CAddModuleFilterDlg 对话框

IMPLEMENT_DYNAMIC(CAddModuleFilterDlg, CDialogEx)

CAddModuleFilterDlg::CAddModuleFilterDlg(ModuleInfoItem* info, CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_ADD_MODULE_FILTER, pParent)
{
    m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
    mModuleInfoItem = info;
}

CAddModuleFilterDlg::~CAddModuleFilterDlg()
{
}

void CAddModuleFilterDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
    DDX_Control(pDX, IDC_LIST1, m_listModuleApis);
    DDX_Control(pDX, IDC_CHECK_ALL, m_checkAll);
    DDX_Control(pDX, IDC_EDIT_NAME, m_editName);
    DDX_Control(pDX, IDC_EDIT_PATH, m_editPath);
    DDX_Control(pDX, IDC_EDIT_BASE, m_editBase);
    DDX_Control(pDX, IDC_CHECK_SAVE_TO_CONFIG, m_checkSaveToConfig);
}


BEGIN_MESSAGE_MAP(CAddModuleFilterDlg, CDialogEx)
    ON_WM_PAINT()
    ON_WM_QUERYDRAGICON()
    ON_BN_CLICKED(IDC_CHECK_ALL, &CAddModuleFilterDlg::OnBnClickedCheckAll)
    ON_NOTIFY(NM_RCLICK, IDC_LIST1, &CAddModuleFilterDlg::OnNMRClickList1)
    ON_COMMAND(IDM_FILTERDLG_SETBREAKPOINT_ALWAYS, &CAddModuleFilterDlg::OnSetbreakpointAlways)
    ON_COMMAND(IDM_FILTERDLG_SETBREAKPOINT_MEETHITTIME, &CAddModuleFilterDlg::OnSetbreakpointMeethittime)
    ON_COMMAND(IDM_FILTERDLG_SETBREAKPOINT_DELETE, &CAddModuleFilterDlg::OnSetbreakpointDelete)
END_MESSAGE_MAP()


// CAddModuleFilterDlg 消息处理程序

const int ListModuleApisColumn_No           = 0;
const int ListModuleApisColumn_Name         = 1;
const int ListModuleApisColumn_VA           = 2;
const int ListModuleApisColumn_Forward      = 3;
const int ListModuleApisColumn_Data         = 4;
const int ListModuleApisColumn_BreakPoint   = 5;

BOOL CAddModuleFilterDlg::OnInitDialog()
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

    m_listModuleApis.SetExtendedStyle(LVS_EX_CHECKBOXES | LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_SIMPLESELECT);
    m_listModuleApis.InsertColumn(ListModuleApisColumn_No           , _T("No."),            LVCFMT_LEFT, 50, -1);
    m_listModuleApis.InsertColumn(ListModuleApisColumn_Name         , _T("Name"),           LVCFMT_LEFT, 120, -1);
    m_listModuleApis.InsertColumn(ListModuleApisColumn_VA           , _T("VA"),             LVCFMT_LEFT, 70, -1);
    m_listModuleApis.InsertColumn(ListModuleApisColumn_Forward      , _T("Forward"),        LVCFMT_LEFT, 120, -1);
    m_listModuleApis.InsertColumn(ListModuleApisColumn_Data         , _T("Data"),           LVCFMT_LEFT, 50, -1);
    m_listModuleApis.InsertColumn(ListModuleApisColumn_BreakPoint   , _T("Break Point"),    LVCFMT_LEFT, 50, -1);

    ASSERT(mModuleInfoItem);
    m_editName.SetWindowText(ToCString(mModuleInfoItem->mName));
    m_editPath.SetWindowText(ToCString(mModuleInfoItem->mPath));
    m_editBase.SetWindowText(ToCString(mModuleInfoItem->mBase, true));

    int idx = 0;
    for (size_t i = 0; i < mModuleInfoItem->mApis.size(); ++i)
    {
        idx = m_listModuleApis.InsertItem(i, _T("---"));
        CString name    = ToCString(mModuleInfoItem->mApis[i].mName);
        CString va      = ToCString(mModuleInfoItem->mApis[i].mVa, true);
        CString forward = ToCString(mModuleInfoItem->mApis[i].mForwardto);
        m_listModuleApis.SetItem(idx, ListModuleApisColumn_Name   , LVIF_TEXT, name, 0, 0, 0, 0);
        m_listModuleApis.SetItem(idx, ListModuleApisColumn_VA     , LVIF_TEXT, va, 0, 0, 0, 0);
        m_listModuleApis.SetItem(idx, ListModuleApisColumn_Forward, LVIF_TEXT, mModuleInfoItem->mApis[i].mIsForward ? forward : _T(""), 0, 0, 0, 0);
        m_listModuleApis.SetItem(idx, ListModuleApisColumn_Data   , LVIF_TEXT, mModuleInfoItem->mApis[i].mIsDataExport ? _T("1") : _T("0"), 0, 0, 0, 0);

        ListView_SetCheckState(m_listModuleApis, idx, 2);
    }
    m_checkAll.SetCheck(true);
    return TRUE;
}

void CAddModuleFilterDlg::OnPaint()
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


HCURSOR CAddModuleFilterDlg::OnQueryDragIcon()
{
    return static_cast<HCURSOR>(m_hIcon);
}


void CAddModuleFilterDlg::OnOK()
{
    ASSERT(m_listModuleApis.GetItemCount() == mModuleInfoItem->mApis.size());
    bool save = m_checkSaveToConfig.GetCheck();
    for (int i = 0; i < mModuleInfoItem->mApis.size(); ++i)
    {
        bool checked = ListView_GetCheckState(m_listModuleApis, i);
        mModuleInfoItem->mApis[i].mIsHook = checked;
        if (save)
        {
            DllFilterConfig::GetConfig()->UpdateApi(mModuleInfoItem->mPath, mModuleInfoItem->mApis[i].mName,
                checked ? DllFilterConfig::kHook : DllFilterConfig::kIgnore);
        }
    }
    if (save)
    {
        DllFilterConfig::GetConfig()->SaveToFile();
    }
    CDialogEx::OnOK();
}


void CAddModuleFilterDlg::OnCancel()
{
    CDialogEx::OnCancel();
}


void CAddModuleFilterDlg::OnBnClickedCheckAll()
{
    UpdateData(TRUE);

    bool checked = m_checkAll.GetCheck();
    ASSERT(m_listModuleApis.GetItemCount() == mModuleInfoItem->mApis.size());
    for (int i = 0; i < mModuleInfoItem->mApis.size(); ++i)
    {
        ListView_SetCheckState(m_listModuleApis, i, checked);
        mModuleInfoItem->mApis[i].mIsHook = checked;
    }

    UpdateData(FALSE);
}



void CAddModuleFilterDlg::OnNMRClickList1(NMHDR *pNMHDR, LRESULT *pResult)
{
    LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);

    CPoint point, clPos;
    GetCursorPos(&point);
    clPos = point;
    m_listModuleApis.ScreenToClient(&clPos);
    int index = m_listModuleApis.HitTest(clPos);
    if (index < 0)
        return;

    m_listModuleApis.SetItemState(index, LVIS_SELECTED, LVIS_SELECTED);
    m_listModuleApis.SetSelectionMark(index);
    CMenu menu;
    menu.LoadMenu(IDR_FILTER_DLG_POP_MENU);
    CMenu *pPopup = menu.GetSubMenu(0);
    pPopup->TrackPopupMenu(TPM_LEFTALIGN | TPM_RIGHTBUTTON, point.x, point.y, this);
    *pResult = 0;
}

void CAddModuleFilterDlg::OnSetbreakpointAlways()
{
    POSITION pos = m_listModuleApis.GetFirstSelectedItemPosition();
    int index = m_listModuleApis.GetNextSelectedItem(pos);
    if (index < 0)
        return;

    if (index >= mModuleInfoItem->mApis.size())
        return;

    TCHAR buffer[512];
    m_listModuleApis.GetItemText(index, ListModuleApisColumn_Name, buffer, sizeof(buffer));
    ASSERT(ToCString(mModuleInfoItem->mApis[index].mName) == buffer);
    mModuleInfoItem->mApis[index].BreakAlways();

    m_listModuleApis.SetItemText(index, ListModuleApisColumn_BreakPoint, ToCString(mModuleInfoItem->mApis[index].GetBpDescription()));
}

void CAddModuleFilterDlg::OnSetbreakpointMeethittime()
{
    mModuleInfoItem->mApis[0].mIsHook;
    CSetBreakPointTimeDialog dlg(this);
    if (IDOK != dlg.DoModal())
        return;

    int times = _wtoi(dlg.m_Times);
    if (times <= 0)
        return;

    POSITION pos = m_listModuleApis.GetFirstSelectedItemPosition();
    int index = m_listModuleApis.GetNextSelectedItem(pos);
    if (index < 0)
        return;

    if (index >= mModuleInfoItem->mApis.size())
        return;

    TCHAR buffer[512];
    m_listModuleApis.GetItemText(index, ListModuleApisColumn_Name, buffer, sizeof(buffer));
    ASSERT(ToCString(mModuleInfoItem->mApis[index].mName) == buffer);
    mModuleInfoItem->mApis[index].BreakOnTime(times);

    m_listModuleApis.SetItemText(index, ListModuleApisColumn_BreakPoint, ToCString(mModuleInfoItem->mApis[index].GetBpDescription()));
}

void CAddModuleFilterDlg::OnSetbreakpointDelete()
{
    POSITION pos = m_listModuleApis.GetFirstSelectedItemPosition();
    int index = m_listModuleApis.GetNextSelectedItem(pos);
    if (index < 0)
        return;

    if (index >= mModuleInfoItem->mApis.size())
        return;

    TCHAR buffer[512];
    m_listModuleApis.GetItemText(index, ListModuleApisColumn_Name, buffer, sizeof(buffer));
    ASSERT(ToCString(mModuleInfoItem->mApis[index].mName) == buffer);
    mModuleInfoItem->mApis[index].RemoveBp();

    m_listModuleApis.SetItemText(index, ListModuleApisColumn_BreakPoint, ToCString(mModuleInfoItem->mApis[index].GetBpDescription()));
}