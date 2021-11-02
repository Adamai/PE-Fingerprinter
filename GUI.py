#!/usr/bin/python
# -*- coding: utf-8 -*-

#This is the GUI

import tkinter as tk
from tkinter.constants import W
from tkinter import filedialog as fd
from tkinter import ttk
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2Tk
from matplotlib.figure import Figure
import PEAnalysisMod as pem
import GraphLinkGen as glg
import webbrowser

import networkx as nx
import matplotlib.pyplot as plt

window = tk.Tk()


searchTypeVar = tk.IntVar()

frame1 = tk.Frame(
    #relief=tk.GROOVE
    #,borderwidth=3
    master=window
)

panedW = tk.PanedWindow(
    master=window
)

frameTree = tk.Frame(
    master=panedW
)
panedW.add(frameTree)

frameFileDetails = tk.Frame(
    master=panedW
)
panedW.add(frameFileDetails)

tab_parent = ttk.Notebook(
    master=frameFileDetails
    ,width=577
)

tab_fileTable = ttk.Frame(
    master=tab_parent
)

tab_fileExternal = ttk.Frame(
    master=tab_parent
)

tab_fileText = ttk.Frame(
    master=tab_parent
)

tab_parent.add(tab_fileTable, text="File Info")
tab_parent.add(tab_fileExternal, text="Threat Ident.")
tab_parent.add(tab_fileText, text="Text Format")


frameLinks = tk.Frame(
    master=tab_fileExternal
    ,bg='#dad5d2'
)

frameScore = tk.Frame(
    master=tab_fileExternal
    ,bg='#dad5d2'
)

frameCanvas = tk.Frame(
    master=panedW
)
panedW.add(frameCanvas)

lbl_greet = tk.Label(
    text="Click the button to load an executable.                                     (This product uses the NVD API but is not endorsed or certified by the NVD.)"
    ,master=frame1
    )

btn_openFile = tk.Button(
    text="Load file"
    ,master=frame1
)

chk_normalSearch = tk.Radiobutton(
    master=frame1
    ,text="Windows search: Look for dependencies in Windows default directory only."
    ,variable=searchTypeVar
    ,value=0
)

chk_localSearch = tk.Radiobutton(
    master=frame1
    ,text="Local directory search: Look for dependencies in file's (sub)directory if not found in Windows directories."
    ,variable=searchTypeVar
    ,value=1
)

chk_prioritizeLocalSearch = tk.Radiobutton(
    master=frame1
    ,text="Prioritize local search: Look for dependencies in file's (sub)directory first. WARNING: Loading all dependencies can take several minutes.                      "
    ,variable=searchTypeVar
    ,value=2
)

lbl_fileName = tk.Label(
    text="File:"
    ,master=frame1
)

btn_openUml = tk.Button(
    text="View in UML-like"
    ,master=frame1
)

tr_fileInfo = ttk.Treeview(
    master=tab_fileTable
    ,height=20
    ,columns=('cValue')
)
tr_fileInfo.column('#0', width=160, stretch=True)
tr_fileInfo.column('cValue', width=400, stretch=True)
tr_fileInfo.heading('#0', text='Property', anchor='w')
tr_fileInfo.heading('cValue', text='Value', anchor='w')

tr_vtInfo = ttk.Treeview(
    master=tab_fileExternal
    ,height=9
    ,columns=('cValue')
)
tr_vtInfo.column('#0', width=450, stretch=True)
tr_vtInfo.column('cValue', width=110, stretch=True)
tr_vtInfo.heading('#0', text='Malware Detection Engines Summary', anchor='w')
tr_vtInfo.heading('cValue', text='Total Results', anchor='w')

tr_nvdInfo = ttk.Treeview(
    master=tab_fileExternal
    ,height=10
    ,columns=('cValue')
)
tr_nvdInfo.column('#0', width=450, stretch=True)
tr_nvdInfo.column('cValue', width=110, stretch=True)
tr_nvdInfo.heading('#0', text='NVD CVE Search', anchor='w')
tr_nvdInfo.heading('cValue', text='Results Found', anchor='w')

scb_fileInfoY = ttk.Scrollbar(
    master=tab_fileTable
    ,orient="vertical"
    ,command=tr_fileInfo.yview
)

scb_fileInfoX = ttk.Scrollbar(
    master=tab_fileTable
    ,orient="horizontal"
    ,command=tr_fileInfo.xview
)

scb_vtInfoY = ttk.Scrollbar(
    master=tab_fileExternal
    ,orient="vertical"
    ,command=tr_vtInfo.yview
)

scb_vtInfoX = ttk.Scrollbar(
    master=tab_fileExternal
    ,orient="horizontal"
    ,command=tr_vtInfo.xview
)

scb_nvdInfoY = ttk.Scrollbar(
    master=tab_fileExternal
    ,orient="vertical"
    ,command=tr_nvdInfo.yview
)

scb_nvdInfoX = ttk.Scrollbar(
    master=tab_fileExternal
    ,orient="horizontal"
    ,command=tr_nvdInfo.xview
)

txt_fileDetails = tk.Text(
    master=tab_fileText
    ,width=69
    ,height=17
)

scb_fileDetails = tk.Scrollbar(
    master=tab_fileText,
    command=txt_fileDetails.yview
)

txt_apiDetails = tk.Text(
    master=tab_fileText
    ,width=69
    ,height=20
)

scb_apiDetails = tk.Scrollbar(
    master=tab_fileText,
    command=txt_apiDetails.yview
)

lbl_linksLabel = tk.Label(
    master=frameLinks
    ,text="Links to results: "
    ,bg='#dad5d2'
)

lbl_linkVT = tk.Label(
    master=frameLinks,
    fg='blue'
    ,cursor="hand2"
    ,bg='#dad5d2'
)

lbl_linkNVDnv = tk.Label(
    master=frameLinks,
    fg='blue'
    ,cursor="hand2"
    ,bg='#dad5d2'
)

lbl_linkNVDmnv = tk.Label(
    master=frameLinks,
    fg='blue'
    ,cursor="hand2"
    ,bg='#dad5d2'
)

lbl_linkNVDn = tk.Label(
    master=frameLinks,
    fg='blue'
    ,cursor="hand2"
    ,bg='#dad5d2'
)

lbl_linkNVDmn = tk.Label(
    master=frameLinks,
    fg='blue'
    ,cursor="hand2"
    ,bg='#dad5d2'
)

lbl_signed = tk.Label(
    master=tab_fileExternal
    ,bg='#dad5d2'
    ,justify="left"
)

lbl_score = tk.Label(
    master=frameScore
    ,bg='#dad5d2'
    ,justify="right"
)

lbl_warningLink = tk.Label(
    master=tab_fileExternal,
    fg='blue'
    ,cursor="hand2"
    ,bg='#dad5d2'
)

style = ttk.Style()
style.theme_use('clam')
streev = ttk.Treeview(
    master=frameTree
)

scb_treeY = ttk.Scrollbar(
    master=frameTree
    ,orient="vertical"
    ,command=streev.yview
)

scb_treeX = ttk.Scrollbar(
    master=frameTree
    ,orient="horizontal"
    ,command=streev.xview
)

notFoundPath = "Not found"

streev.tag_configure(notFoundPath, background='red')
streev.tag_configure('unsurePath', background='yellow')

streev.column('#0', width=200, stretch=True)
streev.heading('#0', text="Simple Dependency View", anchor='w')

window.title("PE Fingerprinter")
window.minsize(width=1500, height=720)
frame1.grid(row=0,column=0, sticky="new", columnspan=5)
window.grid_columnconfigure(0, weight=2)
panedW.grid(row=1,column=0, sticky="nsew")
#frameTree.grid(row=1,column=0, sticky="nsew")
window.grid_rowconfigure(1, weight=1)
window.grid_rowconfigure(2, weight=1)
frameTree.grid_rowconfigure(0, weight=1)
frameTree.grid_columnconfigure(0, weight=1)
#frameFileDetails.grid(row=1,column=1, sticky="nsw")
tab_parent.grid(row=0, column=0, sticky="nswe")
frameLinks.grid(row=4, column=0, sticky="nw")
frameScore.grid(row=5, column=0, sticky="ne")
#frameCanvas.grid(row=1,column=2,sticky="nw")
frameCanvas.grid_rowconfigure(1, weight=3)

lbl_greet.grid(row=0,column=0, sticky="nw")
lbl_fileName.grid(row=1,column=0, sticky="nw")
btn_openFile.grid(row=2,column=0, sticky="nw")
chk_normalSearch.grid(row=3, column=0, sticky="nw")
chk_localSearch.grid(row=4, column=0, sticky="nw")
chk_prioritizeLocalSearch.grid(row=5, column=0, sticky="nw")
streev.grid(row=0, column=0, sticky="nswe")
scb_treeX.grid(row=1,column=0,sticky="nwe")
scb_treeY.grid(row=0,column=1,sticky="nsw")
streev.configure(xscrollcommand=scb_treeX.set, yscrollcommand=scb_treeY.set)
tr_fileInfo.grid(row=0,column=0, sticky="nwe")
scb_fileInfoY.grid(row=0,column=1,sticky="nsw")
scb_fileInfoX.grid(row=1,column=0,sticky="nwe")
tr_fileInfo.configure(xscrollcommand=scb_fileInfoX.set, yscrollcommand=scb_fileInfoY.set)
tr_vtInfo.grid(row=0,column=0, sticky="nwe")
scb_vtInfoY.grid(row=0,column=1,sticky="nsw")
scb_vtInfoX.grid(row=1,column=0,sticky="nwe")
tr_vtInfo.configure(xscrollcommand=scb_vtInfoX.set, yscrollcommand=scb_vtInfoY.set)
tr_nvdInfo.grid(row=2,column=0, sticky="nwe")
scb_nvdInfoY.grid(row=2,column=1,sticky="nsw")
scb_nvdInfoX.grid(row=3,column=0,sticky="nwe")
tr_nvdInfo.configure(xscrollcommand=scb_nvdInfoX.set, yscrollcommand=scb_nvdInfoY.set)
txt_fileDetails.grid(row=0,column=0, sticky="nw")
scb_fileDetails.grid(row=0,column=1, sticky="nsw")
txt_fileDetails['yscrollcommand']=scb_fileDetails.set
txt_apiDetails.grid(row=1,column=0, sticky="nw")
scb_apiDetails.grid(row=1,column=1, sticky="nsw")
txt_apiDetails['yscrollcommand']=scb_apiDetails.set
lbl_linksLabel.pack(side='left')
lbl_linkVT.pack(side='left')
lbl_linkNVDnv.pack(side='left')
lbl_linkNVDmnv.pack(side='left')
lbl_linkNVDn.pack(side='left')
lbl_linkNVDmn.pack(side='left')
lbl_signed.grid(row=5, column=0, sticky="nw")
lbl_score.pack(side='right')
lbl_warningLink.grid(row=6, column=0, sticky="nw")

fig = Figure(figsize=(7.3, 6.1), dpi=100)
canvas = FigureCanvasTkAgg(fig, frameCanvas)
canvas.get_tk_widget().pack(side='top')
toolbar = NavigationToolbar2Tk(canvas, frameCanvas)

G = nx.Graph()
fullDlls = []
fullDllsInfo = []
gfileName = ''
deepLocalSearch = False

def loadFile(filepath):
    global canvas
    global toolbar
    global fig

    #Variables for score
    isSignatureValid = False
    nCVEcurVer = 0
    nCVEallVer = 0
    VTtotal = 0
    VTmalic = 0
    VTsus = 0
    nOutDepend = 0
    
    canvas.get_tk_widget().delete("all")
    canvas.get_tk_widget().destroy()
    toolbar.destroy()
    plt.close(fig)

    fig = Figure(figsize=(7.3, 6.1), dpi=100)
    fig.subplots_adjust(left=0, bottom=0, right=1, top=1, wspace=None, hspace=None)
    canvas = FigureCanvasTkAgg(fig, frameCanvas)
    canvas.get_tk_widget().pack(side='top')
    toolbar = NavigationToolbar2Tk(canvas, frameCanvas)
    toolbar.update()

    global gfileName
    lbl_fileName["text"] = "File: " + filepath
    fileName = filepath.rpartition('/')[2]
    fileName = fileName.rpartition('\\')[2]
    gfileName = fileName

    global fullDlls
    global fullDllsInfo
    boolLocalSearch = False
    boolPrioritizeLocal = False
    if(searchTypeVar.get() == 0):
        boolLocalSearch = False
        boolPrioritizeLocal = False
    elif(searchTypeVar.get() == 1):
        boolLocalSearch = True
        boolPrioritizeLocal = False
    elif(searchTypeVar.get() == 2):
        boolLocalSearch = False
        boolPrioritizeLocal = True

    fullDlls = pem.getDLLs(filepath, boolLocalSearch, boolPrioritizeLocal)
    fullDllsInfo = []
    #have a show dependencies button in the UML if possible to load the dependencies of the DLLs from their path
    #print(fullDlls[0].name)
    #print(fullDlls[0].path)
    #print(fullDlls[0].unsurePathFlag)
    #print(fullDlls[0].functions)
    details = ""
    fullDllsInfo.append(pem.getFileInfo(filepath))
    fileInfo = fullDllsInfo[0]
    fileVersion = None
    for info in fileInfo:
        details = details + info + ": " + fileInfo[info] + "\n"
        if("ProductVersion" in info or "FileVersion" in info):
            fileVersion = str(fileInfo[info])
    txt_fileDetails.delete('1.0', 'end')
    txt_fileDetails.insert('1.0', "File Details\n"+details)
    
    G.clear()
    labeldict = {}
    G.add_node(fileName)
    labeldict[fileName] = fileName

    #inserting tkinter simple tree view text
    #DISPLAY IMPORTED FUNCTIONS IN  ANOTHER TAB/TABLE
    streev.delete(*streev.get_children())
    tr_nvdInfo.delete(*tr_nvdInfo.get_children())
    tr_vtInfo.delete(*tr_vtInfo.get_children())

    itemId = 0
    for dll in fullDlls:
        if(dll.path == notFoundPath or dll.path == None or dll.path == ''):
            streev.insert('', 'end', tags=[notFoundPath], text=dll.name + ' (NF)', iid=itemId)
        elif(dll.unsurePathFlag):
            streev.insert('', 'end', tags=('unsurePath'), text=dll.name + ' (U)', iid=itemId)
            subDlls = pem.getDLLsNoSearch(dll.path)
            fullDllsInfo.append(pem.getFileInfo(dll.path))
            for subDll in subDlls:
                streev.insert(str(itemId), 'end', text=subDll.name)
        else:
            streev.insert('', 'end', text=dll.name, iid=itemId)
            subDlls = pem.getDLLsNoSearch(dll.path)
            fullDllsInfo.append(pem.getFileInfo(dll.path))
            for subDll in subDlls:
                streev.insert(str(itemId), 'end', text=subDll.name)
        itemId=itemId+1
        G.add_node(dll.name)
        G.add_edge(fileName, dll.name)
        
        labeldict[dll.name] = dll.name

        if(not(':\\Windows\\' in dll.path)):
            nOutDepend = nOutDepend + 1
            print(dll.path)

    fileIntoTable(fileName)

    try:
        vtInfo = pem.getVTinfo(fileInfo['SHA256'])
    except:
        vtInfo = None
    finally:
        if(vtInfo is None):
            txt_apiDetails.delete('1.0', 'end')
            txt_apiDetails.insert('end', "No data for this file found on VirusTotal database. It would be great if you could upload it.\nhttps://www.virustotal.com/gui/home/upload")
            lbl_linkVT['text']=""
            lbl_linkVT.unbind_all("<Button-1>")
            tr_vtInfo.insert('', 'end', text='File not in VirusTotal Database. Use the link in "Text Format" tab to upload it.')
        else:
            lbl_signed['text'] = 'File signature status: Unsigned'
            if(hasattr(vtInfo, 'signature_info')):
                if('verified' in vtInfo.signature_info ):
                    lbl_signed['text'] = "File signature status: "+ vtInfo.signature_info['verified']
                    if(vtInfo.signature_info['verified'] == 'Signed'):
                        isSignatureValid = True
                if('signers' in vtInfo.signature_info):
                    lbl_signed['text'] += "\nSignatures: " + str(vtInfo.signature_info['signers']).replace('; ', '\n                     ')

            txt_apiDetails.delete('1.0', 'end')
            txt_apiDetails.insert('end', "  VirusTotal API results\n"+"Meaningful file name: "+vtInfo.meaningful_name+"\n\nEngines analysis summary:")
            for result in vtInfo.last_analysis_stats:
                txt_apiDetails.insert('end', '\n'+str(result)+": "+str(vtInfo.last_analysis_stats[result]))
                tr_vtInfo.insert('', 'end', text=str(result), values=(str(vtInfo.last_analysis_stats[result]),))

                VTtotal = VTtotal + vtInfo.last_analysis_stats[result]
                if(str(result) == 'malicious'):
                    VTmalic = vtInfo.last_analysis_stats[result]
                elif(str(result) == 'suspicious'):
                    VTsus = vtInfo.last_analysis_stats[result]
                elif('unsupported' in str(result)):
                    VTtotal = VTtotal - vtInfo.last_analysis_stats[result]
                elif('timeout' in str(result)):
                    VTtotal = VTtotal - vtInfo.last_analysis_stats[result]

            txt_apiDetails.insert('end', '\n\nFor more info on the results click the VirusTotal link below this box or visit: https://www.virustotal.com/gui/file/'+fileInfo['SHA256'])
            lbl_linkVT['text']="VirusTotal"
            lbl_linkVT.bind("<Button-1>", lambda event: webbrowser.open('https://www.virustotal.com/gui/file/'+fileInfo['SHA256']))
            #Put tip on link later

        #display NVD query results with FileName, meaningful_name, and both + version number
        txt_apiDetails.insert('end', '\n\n  NVD CVE Results')
        
        if(fileVersion is not None):
            #COMMENT THIS NEXT LINE
            #fileVersion = '10.5.55.33574'
            nvdjson = pem.getCVEresults(fileName +"+"+ fileVersion)
            if(nvdjson['totalResults'] < 1):
                #Fix for versions with commas instead of dot
                fileVersion = str(fileVersion).replace(',', '.')
                nvdjson = pem.getCVEresults(fileName +"+"+ fileVersion)
            txt_apiDetails.insert('end', '\nUsing current file name and version('+fileName+' '+fileVersion+'):')
            txt_apiDetails.insert('end', '\nTotal results: '+str(nvdjson['totalResults']))
            
            tr_nvdInfo.insert('', 'end', text='Using current file name and version('+fileName+' '+fileVersion+')', values=(str(nvdjson['totalResults']),), iid='name+v')
            #Display CVEs and link to them.
            if(nvdjson['totalResults'] > 0):
                txt_apiDetails.insert('end', '\n Source: ' + 'https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&search_type=all&isCpeNameSearch=false&query='+fileName+'+'+fileVersion)
                nCVEcurVer = nvdjson['totalResults']
                for CVE in nvdjson['result']['CVE_Items']:
                    txt_apiDetails.insert('end', "\n "+str(CVE['cve']['CVE_data_meta']['ID']))
                    tr_nvdInfo.insert('name+v', 'end', text=str(CVE['cve']['CVE_data_meta']['ID']))
                lbl_linkNVDnv['text']="NVD_File+Version"
                lbl_linkNVDnv.bind("<Button-1>", lambda event: webbrowser.open('https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&search_type=all&isCpeNameSearch=false&query='+fileName+'+'+fileVersion))
            else:
                lbl_linkNVDnv['text']=""
                lbl_linkNVDnv.unbind_all("<Button-1>")
        if(vtInfo is not None):
            if(fileVersion is not None and vtInfo.meaningful_name != fileName):
                nvdjson = pem.getCVEresults(vtInfo.meaningful_name +"+"+ fileVersion)
                if(nvdjson['totalResults'] < 1):
                    fileVersion = str(fileVersion).replace(',', '.')
                    nvdjson = pem.getCVEresults(vtInfo.meaningful_name +"+"+ fileVersion)
                txt_apiDetails.insert('end', '\nUsing VT meaningful name and version('+vtInfo.meaningful_name+' '+fileVersion+'):')
                txt_apiDetails.insert('end', '\nTotal results: '+str(nvdjson['totalResults']))
                tr_nvdInfo.insert('', 'end', text='Using VT meaningful name and version('+vtInfo.meaningful_name+' '+fileVersion+')', values=(str(nvdjson['totalResults']),), iid='Mname+v')
                if(nvdjson['totalResults'] > 0):
                    txt_apiDetails.insert('end', '\n Source: ' + 'https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&search_type=all&isCpeNameSearch=false&query='+vtInfo.meaningful_name+'+'+fileVersion)
                    if(nCVEcurVer < nvdjson['totalResults']):
                        nCVEcurVer = nvdjson['totalResults']
                    for CVE in nvdjson['result']['CVE_Items']:
                        txt_apiDetails.insert('end', "\n "+str(CVE['cve']['CVE_data_meta']['ID']))
                        tr_nvdInfo.insert('Mname+v', 'end', text=str(CVE['cve']['CVE_data_meta']['ID']))
                    lbl_linkNVDmnv['text']="NVD_MeaningfulName+Version"
                    lbl_linkNVDmnv.bind("<Button-1>", lambda event: webbrowser.open('https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&search_type=all&isCpeNameSearch=false&query='+vtInfo.meaningful_name+'+'+fileVersion))
                else:
                    lbl_linkNVDmnv['text']=""
                    lbl_linkNVDmnv.unbind_all("<Button-1>")

        txt_apiDetails.insert('end', '\nUsing current file name('+fileName+'):')
        nvdjson = pem.getCVEresults(fileName)
        txt_apiDetails.insert('end', '\nTotal results: '+str(nvdjson['totalResults']))
        tr_nvdInfo.insert('', 'end', text='Using current file name('+fileName+')', values=(str(nvdjson['totalResults']),), iid='name')
        if(nvdjson['totalResults'] > 0):
            txt_apiDetails.insert('end', '\n Source: ' + 'https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&search_type=all&isCpeNameSearch=false&query='+fileName)
            nCVEallVer = nvdjson['totalResults']
            for CVE in nvdjson['result']['CVE_Items']:
                tr_nvdInfo.insert('name', 'end', text=str(CVE['cve']['CVE_data_meta']['ID']))
            lbl_linkNVDn['text']="NVD_FileName"
            lbl_linkNVDn.bind("<Button-1>", lambda event: webbrowser.open('https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&search_type=all&isCpeNameSearch=false&query='+fileName))
        else:
            lbl_linkNVDn['text']=""
            lbl_linkNVDn.unbind_all("<Button-1>")

        if(vtInfo is not None):
            if(vtInfo.meaningful_name != fileName):
                txt_apiDetails.insert('end', '\nUsing VT meaningful name('+vtInfo.meaningful_name+'):')
                nvdjson = pem.getCVEresults(vtInfo.meaningful_name)
                txt_apiDetails.insert('end', '\n Total results: '+str(nvdjson['totalResults']))
                tr_nvdInfo.insert('', 'end', text='Using VT meaningful name('+vtInfo.meaningful_name+')', values=(str(nvdjson['totalResults']),), iid='Mname')
                if(nvdjson['totalResults'] > 0):
                    txt_apiDetails.insert('end', '\n Source: ' + 'https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&search_type=all&isCpeNameSearch=false&query='+vtInfo.meaningful_name)
                    if(nCVEallVer < nvdjson['totalResults']):
                        nCVEallVer = nvdjson['totalResults']
                    for CVE in nvdjson['result']['CVE_Items']:
                        tr_nvdInfo.insert('Mname', 'end', text=str(CVE['cve']['CVE_data_meta']['ID']))
                    lbl_linkNVDmn['text']="NVD_MeaningfulName"
                    lbl_linkNVDmn.bind("<Button-1>", lambda event: webbrowser.open('https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&search_type=all&isCpeNameSearch=false&query='+vtInfo.meaningful_name))
                else:
                    lbl_linkNVDmn['text']=""
                    lbl_linkNVDmn.unbind_all("<Button-1>")

        
        pos = nx.planar_layout(G)
        nx.draw(G, pos=pos, ax=fig.gca(), with_labels=True, labels=labeldict, node_shape="s",  node_color="none", bbox=dict(facecolor="skyblue", edgecolor='black', boxstyle='round,pad=0.2'))
        
        #glg.getUMLdot(fileName , fullDlls)
        btn_openUml.grid(row=5, column=10, sticky="se")

        canvas.draw()

        #Display Safety score:
        # Not valid signature (20)
        deductSignature = 0
        if(not isSignatureValid):
            deductSignature = 20
        # CVE in current version (20 + 2*n) (upper limit: 30)
        deductCVEcurVer = 0
        if(nCVEcurVer > 0):
            deductCVEcurVer = 20 + 2 * nCVEcurVer
            if deductCVEcurVer > 30:
                deductCVEcurVer = 30
        # CVE in past versions (5 + 1*n) (upper limit: 20)
        deductCVEpastVer = 0
        if(nCVEallVer > nCVEcurVer):
            deductCVEpastVer =  5 + (nCVEallVer - nCVEcurVer)
            if deductCVEpastVer > 20:
                deductCVEpastVer = 20
        # VT malware analysis ((Malicious + Suspicious)/Total-unsupported-timouts-failure)
        deductVTscan = 80 * ((VTsus + VTmalic)/VTtotal)
        # Number of outside dependencies (10)
        deductOutDep = nOutDepend
        if deductOutDep > 10:
            deductOutDep = 10

        trustScore = 100 - deductSignature - deductCVEcurVer - deductCVEpastVer - deductVTscan - deductOutDep
        print(deductSignature)
        print(deductCVEcurVer)
        print(deductCVEpastVer)
        print(deductVTscan)
        print(deductOutDep)
        
        if trustScore < 0:
            trustScore = 0
        
        lbl_score['text'] = 'Safety score:\n' + str(trustScore)+'%\n\n\n\nThis score is an estimated value based on the findings of this application.\nThe use of a proper malware defense tool is recommended.'
        if(trustScore < 70):
            lbl_score['fg'] = '#8B0000'
        elif(trustScore < 90):
            lbl_score['fg'] = '#CC7000'
        lbl_warningLink['text'] = 'Refer to https://nvd.nist.gov for the latest vulnerability discoveries and updates.'
        lbl_warningLink.bind("<Button-1>", lambda event: webbrowser.open('https://nvd.nist.gov/'))
        txt_apiDetails.insert('end', '\n\nSafety score: ' + str(trustScore)+'%')
        


def fileIntoTable(fileName):
    tr_fileInfo.delete(*tr_fileInfo.get_children())
    for fileInfo in fullDllsInfo:
        if(fileInfo['CurrentFileName'] == fileName):
            for info in fileInfo:
                tr_fileInfo.insert('', 'end', text=info, values=(fileInfo[info],))
                #print(fileInfo[info])
            


def loadFileWbutton(event):
    filepath = fd.askopenfilename(
        filetypes=[("PE Files", "*.acm *.ax *.cpl *.dll *.drv *.efi *.exe *.mui *.ocx, *.scr *.sys *.tsp"), ("All Files", "*.*")]
    )
    if not filepath:
        return
    loadFile(filepath)

btn_openFile.bind("<Button-1>", loadFileWbutton)

def loadDependencyDClick(event):
    item = streev.identify('item', event.x, event.y)
    itemName = streev.item(item, 'text')
    for dll in fullDlls:
        if(dll.name == itemName):
            loadFile(dll.path)
            return

streev.bind("<Double-1>", loadDependencyDClick)

def viewUmlbutton(event):
    try:
        glg.getUMLdot(gfileName, fullDlls)
    except:
        webbrowser.open(glg.getUMLrestAddress(glg.getUMLdotNoFunctions(gfileName, fullDlls)))

btn_openUml.bind("<Button-1>", viewUmlbutton)

window.mainloop()