#!/usr/bin/python
# -*- coding: utf-8 -*-


from graphviz import Source
#import requests

def getUMLdot(mainFileName, fullDlls):
    mfn = ''.join(c for c in str(mainFileName) if c.isalnum())
    umlDot = 'digraph UML {\n'
    umlDot += 'node [fontname = "Arial"; fontsize = 11; shape = "record"];\nedge [arrowhead="empty"]\n'
    umlDot += mfn + '[label=" { '+mainFileName+'|| }"];\n'

    #CONTINUE BY LOOPING THROUGH FULLDLLS
    for dll in fullDlls:
        dlln = ''.join(c for c in str(dll.name) if c.isalnum())

        umlDot += dlln +'[label=" { ' + dll.name + '||\\n'
        for function in dll.functions:
            umlDot += str(function) + '()\\n'
        umlDot += ' }" ];\n' + mfn + ' -> ' + dlln + ';\n'

    umlDot += ' } '
    #print(umlDot)

    s = Source(umlDot, filename=mainFileName+"UML.png", format="png")
    #s.render(filename='testing.png')
    s.view()

    #(graph,) = pydot.graph_from_dot_data((umlDot))
    #graph.write_png('somefile.png')

    return umlDot

def getUMLdotNoFunctions(mainFileName, fullDlls):
    mfn = ''.join(c for c in str(mainFileName) if c.isalnum())
    umlDot = 'digraph UML {\n'
    umlDot += 'node [fontname = "Arial"; fontsize = 11; shape = "record"];\nedge [arrowhead="empty"]\n'
    umlDot += mfn + '[label=" { '+mainFileName+'|| }"];\n'

    #CONTINUE BY LOOPING THROUGH FULLDLLS
    for dll in fullDlls:
        dlln = ''.join(c for c in str(dll.name) if c.isalnum())
        umlDot += dlln +'[label=" { ' + dll.name + '||\\n'
        umlDot += ' }" ];\n' + mfn + ' -> ' + dlln + ';\n'

    umlDot += ' } '
    #print(umlDot)
    return umlDot

    
#def getUMLrestImage(umlDot):
#    response = requests.get("https://quickchart.io/graphviz?format=png&graph="+umlDot)
#    if response.status_code == 200:
#        return response

def getUMLrestAddress(umlDot):
    return "https://quickchart.io/graphviz?format=png&graph="+umlDot


#digraph Couriers {node [fontname = "Arial";\nfontsize = 11;\nshape = "record"]

#edge [arrowtail = "empty"]

#Courier [
#label = "{Courier|+ name : string\l+ home_country : string\l|+ calculateShipping() : float\l+ ship(): boolean\l}"
#]

#Monotype [
#label = "{MonotypeDelivery|\l|+ ship(): boolean\l}"
#]

#Pigeon [
#label = "{PigeonPost|\l|+ ship(): boolean\l}"
#]

#Courier -> Pigeon [dir=back];\nCourier -> Monotype [dir=back];\nPigeon->Monotype
#}