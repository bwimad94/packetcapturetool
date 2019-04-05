/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package newpacketcapt;

/**
 *
 * @author SHADOW
 */
import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import jpcap.*;
import jpcap.packet.Packet;
import jpcap.packet.IPPacket;
import jpcap.packet.TCPPacket;
import java.io.*;
import java.util.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.mail.*;
import javax.mail.internet.*;
import java.util.regex.*;

public class NewPacketCapt {

    JpcapWriter writer;
    NetworkInterface[] NET_INTERFACES;
    JpcapCaptor CAPTOR;
    PacketCaptThread CAPTURE_THREAD;
    int INDEX = 0;
    int COUNT = 0;
    boolean CaptStatus = false;
    boolean filterActivated = false;
    public static File file;
    JFrame Frame = new JFrame("PacketCapt v1.0");
    public static JTextArea OUTPUT_WINDOW = new JTextArea();
    JScrollPane OUTPUT_SCROLL = new JScrollPane();
    ButtonGroup FILTER_GRP = new ButtonGroup();
    ButtonGroup PORTS_GRP = new ButtonGroup();
    JButton CAPTURE = new JButton("Capture");
    JButton STOP = new JButton("Stop");
    JButton SELECT = new JButton("Select");
    JButton LIST = new JButton("List");

    JButton SAVE = new JButton("Save");
    JButton LOAD = new JButton("Load");
    JButton ABOUT = new JButton("About");
    JButton HELP = new JButton("Help");
    JButton EXIT = new JButton("Exit");
    JLabel Title = new JLabel("PacketCapt v1.0");
    JLabel Interface = new JLabel("GUI");

    JTextField SelectInt = new JTextField();
    JTextField CustomPort = new JTextField();
    JTextField filterPkt = new JTextField();
    JFileChooser fc = new JFileChooser();
    JButton enter = new JButton("Filter");
    JButton synAttack = new JButton("TCP Analyse");
    String path = "";
    JButton sites = new JButton("Sites Visited");

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        // TODO code application logic here
        new NewPacketCapt();

    }

    public NewPacketCapt() {
        

        BuildInterface();
        DisableButtons();

    }

    public void BuildInterface() {

        Frame.setSize(865, 580);
        Frame.setLocation(200, 200);
        Frame.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
        Frame.getContentPane().setLayout(null);

        OUTPUT_WINDOW.setEditable(false);
        OUTPUT_WINDOW.setFont(new Font("Monospaced", 0, 12));
        OUTPUT_WINDOW.setForeground(new Color(0, 0, 153));
        OUTPUT_WINDOW.setLineWrap(true);

        OUTPUT_SCROLL.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        OUTPUT_SCROLL.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
        OUTPUT_SCROLL.setViewportView(OUTPUT_WINDOW);

        Frame.getContentPane().add(OUTPUT_SCROLL);
        OUTPUT_SCROLL.setBounds(10, 16, 840, 390);

        CAPTURE.setBackground(new Color(255, 0, 0));
        CAPTURE.setForeground(new Color(255, 255, 255));
        CAPTURE.setMargin(new Insets(0, 0, 0, 0));
        CAPTURE.addActionListener(new ActionListener() {

            public void actionPerformed(ActionEvent E) {

                Action_CAPTURE(E);

            }

        });

        Frame.getContentPane().add(CAPTURE);
        CAPTURE.setBounds(5, 410, 110, 25);

        STOP.setBackground(new Color(0, 0, 0));
        STOP.setForeground(new Color(255, 255, 255));
        STOP.setMargin(new Insets(0, 0, 0, 0));
        STOP.addActionListener(new ActionListener() {

            public void actionPerformed(ActionEvent E) {

                Action_STOP(E);

            }

        });
        Frame.getContentPane().add(STOP);
        STOP.setBounds(125, 410, 130, 25);

        SELECT.setBackground(new Color(0, 0, 0));
        SELECT.setForeground(new Color(255, 255, 255));
        SELECT.setMargin(new Insets(0, 0, 0, 0));
        SELECT.addActionListener(new ActionListener() {

            public void actionPerformed(ActionEvent E) {

                Action_SELECT(E);

            }

        });
        Frame.getContentPane().add(SELECT);
        SELECT.setBounds(5, 488, 75, 20);

        LIST.setBackground(new Color(0, 0, 0));
        LIST.setForeground(new Color(255, 255, 255));
        LIST.setMargin(new Insets(0, 0, 0, 0));
        LIST.addActionListener(new ActionListener() {

            public void actionPerformed(ActionEvent E) {

                Action_LIST(E);

            }

        });
        Frame.getContentPane().add(LIST);
        LIST.setBounds(5, 510, 75, 20);

        LOAD.setBackground(new Color(0, 0, 0));
        LOAD.setForeground(new Color(255, 255, 255));
        LOAD.setMargin(new Insets(0, 0, 0, 0));
        LOAD.addActionListener(new ActionListener() {

            public void actionPerformed(ActionEvent E) {

                Action_LOAD(E);

            }

        });
        Frame.getContentPane().add(LOAD);
        LOAD.setBounds(125, 464, 75, 25);

        EXIT.setBackground(new Color(0, 0, 0));
        EXIT.setForeground(new Color(255, 255, 255));
        EXIT.setMargin(new Insets(0, 0, 0, 0));
        EXIT.addActionListener(new ActionListener() {

            public void actionPerformed(ActionEvent E) {

                Action_EXIT(E);

            }

        });
        Frame.getContentPane().add(EXIT);
        EXIT.setBounds(125, 500, 75, 25);

        SelectInt.setForeground(new Color(255, 0, 0));
        SelectInt.setHorizontalAlignment(JTextField.CENTER);
        Frame.getContentPane().add(SelectInt);
        SelectInt.setBounds(5, 464, 70, 20);

        filterPkt.setForeground(new Color(255, 0, 0));
        filterPkt.setHorizontalAlignment(JTextField.CENTER);
        Frame.getContentPane().add(filterPkt);
        filterPkt.setBounds(300, 410, 300, 30);

        enter.setBackground(new Color(0, 0, 0));
        enter.setForeground(new Color(255, 255, 255));
        enter.setMargin(new Insets(0, 0, 0, 0));
        enter.addActionListener(new ActionListener() {

            public void actionPerformed(ActionEvent E) {

                Action_ENTER(E);

            }

        });
        Frame.getContentPane().add(enter);
        enter.setBounds(605, 412, 80, 25);

        synAttack.setBackground(new Color(0, 0, 0));
        synAttack.setForeground(new Color(255, 255, 255));
        synAttack.setMargin(new Insets(0, 0, 0, 0));
        synAttack.addActionListener(new ActionListener() {

            public void actionPerformed(ActionEvent E) {

                Action_SYNDETECT(E);

            }

        });
        Frame.getContentPane().add(synAttack);
        synAttack.setBounds(300, 450, 110, 25);

        sites.setBackground(new Color(0, 0, 0));
        sites.setForeground(new Color(255, 255, 255));
        sites.setMargin(new Insets(0, 0, 0, 0));
        sites.addActionListener(new ActionListener() {

            public void actionPerformed(ActionEvent E) {

                Action_SITESVISITED(E);

            }

        });
        Frame.getContentPane().add(sites);
        sites.setBounds(300, 500, 110, 25);

        Frame.setVisible(true);

    }

    public void Action_CAPTURE(ActionEvent E) {
        
        try {

            OUTPUT_WINDOW.setText("");
            CaptStatus = true;
            captPackets();
        } catch (Exception Ex) {

        }

    }

    public void Action_STOP(ActionEvent E) {
        try {
            CaptStatus = false;
            CAPTURE_THREAD.ended();
            writer.close();

        } catch (Throwable Ex) {

            //System.out.println(Ex);
        }

    }

    public void Action_SITESVISITED(ActionEvent E) {
        
        try{

        CaptStatus = true;
        visited();}
        catch(Exception Ex){
        
        }

    }

    public void Action_SELECT(ActionEvent E) {
        
        try{

        SelectInterface();
        }
        catch(Exception Ex){
        
        }

    }

    public void Action_LIST(ActionEvent E) {
        
        try{

        ListNetInterfaces();
        SELECT.setEnabled(true);
        SelectInt.requestFocus();}
        catch(Exception Ex){
        }

    }

    public void Action_ENTER(ActionEvent E) {
        try{
        CaptStatus = true;
        String content = filterPkt.getText();
        Filter(content);}
        catch(Exception Ex){
        
        }
    }

    public void Action_LOAD(ActionEvent E) {
        try{
        CaptStatus = true;
        loadDump();}
        catch (Exception Ex){
        
        
        }
    }

 

    public void Action_EXIT(ActionEvent E) {
        
        try{

        Frame.setVisible(false);
        Frame.dispose();}
        catch (Exception Ex){
        
        }

    }

    public void Action_SYNDETECT(ActionEvent E) {
        try{
        CaptStatus = true;
        tcpFilter();}
        catch(Exception Ex){
        }

    }

    public void ListNetInterfaces() {
        try{

        NET_INTERFACES = JpcapCaptor.getDeviceList();//Get all interfaces to the array
        OUTPUT_WINDOW.setText("");

        for (int i = 0; i < NET_INTERFACES.length; i++) {

            OUTPUT_WINDOW.append("\n\n---------------------------------Interface" + i
                    + "Info----------------------------------------------");
            OUTPUT_WINDOW.append("\nInterface Number: " + i);//Append interface number
            OUTPUT_WINDOW.append("\nDescription "//Appends the interface name and description
                    + NET_INTERFACES[i].name + "{"
                    + NET_INTERFACES[i].description + "}");
            OUTPUT_WINDOW.append("\nDatalink Name: "//Appends datalink layer information
                    + NET_INTERFACES[i].datalink_name + "{"
                    + NET_INTERFACES[i].datalink_description + "}");
            OUTPUT_WINDOW.append("\nMAC address:");//Append the MAC address

            byte[] Y = NET_INTERFACES[i].mac_address;
            for (int x = 0; x <= NET_INTERFACES.length; x++) {

                OUTPUT_WINDOW.append(Integer.toHexString(Y[x] & 0xff) + ":");//Convresion of MAC address to a HEX String 

            }

            for (NetworkInterfaceAddress INTF : NET_INTERFACES[i].addresses) {//prinnts IP address,subnet mask and broadcast address

                OUTPUT_WINDOW.append("\nIP Address :" + INTF.address);
                OUTPUT_WINDOW.append("\nSubnet Mask :" + INTF.subnet);
                OUTPUT_WINDOW.append("\nBroadcast Address :" + INTF.broadcast);

            }

            COUNT++;

        }
        }
        catch (Exception Ex){
        
        }

    }

    public void SelectInterface() {
        try{

        int temp = Integer.parseInt(SelectInt.getText());//get text from JTextArea as inetegr

        if (temp > -1 && temp < COUNT) {//checks if the user input is in valid range

            INDEX = temp;//assign global variable INDEX the user input interface number
            EnableButtons();//enables disabled buttons

        } else {

            JOptionPane.showMessageDialog(
                    null, "Outside of range # interface = 0-" + (COUNT - 1) + ".");//shows error if the user inputs an interface out of range

        }

        SelectInt.setText("");}
        catch(Exception Ex){
        
        }

    }

    public void captPackets() {
        String[] button = {"View & Save", "View Only"};
        int option = JOptionPane.showOptionDialog(null, "Select option", "Select Option", JOptionPane.INFORMATION_MESSAGE, 0, null, button, button[1]);

        if (option == 0) {
            try{

            JFileChooser fc = new JFileChooser(new File("c:\\"));
            FileNameExtensionFilter filter = new FileNameExtensionFilter("Captured Packets", " ");
            fc.setFileFilter(filter);
            int result = fc.showOpenDialog(null);
            if (result == JFileChooser.APPROVE_OPTION) {

                file = fc.getSelectedFile();
            }
            }
            catch(Exception Ex){
            
            
            }
            CAPTURE_THREAD = new PacketCaptThread() {

                public Object construct() {
                    OUTPUT_WINDOW.setText("\nNow Capturing on interface " + INDEX + "..."
                            + "\n--------------------------------------------------"
                            + "----------------------------------------------\n\n");

                    try {

                        CAPTOR = JpcapCaptor.openDevice(NET_INTERFACES[INDEX], 65535, false, 20);//opens new device interface
                        CAPTOR.setFilter("ip", true);//show only IPv4

                        String name = file.getAbsolutePath();
                        String format = "";
                        JpcapWriter writer = JpcapWriter.openDumpFile(CAPTOR, name);//opens a dump file to save the captured packets
                        while (CaptStatus) {//while true
                            try {
                                Packet packet = CAPTOR.getPacket();//Captures a packet

                                if (packet == null) { //if the packet is null return to start of the loop
                                    continue;
                                }
                                format = packet.toString();
                                //removes unncessary elements of packet from showing the user
                                format = format.replace("protocol", "");
                                format = format.replace("priority", "");
                                format = format.replace("hop", "");
                                format = format.replace("offset", "");
                                format = format.replace("ident", "");
                                format = format.replaceAll("\\(.*?\\)", "");

                                OUTPUT_WINDOW.append(
                                        format
                                        + "\n--------------------------------------------------"
                                        + "-----------------------------------------------\n\n");
                                try {
                                    writer.writePacket(packet);//writes packet to file
                                } catch (Throwable E) {

                                    System.out.println(E);
                                    continue;

                                }

                            } catch (Exception NullPointerException) {

                            }

                            // 
                        }

                        CAPTOR.close(); //closes the capturing process
                        OUTPUT_WINDOW.append("\nCapturing Ended.....");

                    } catch (Exception Ex) {

                        System.out.println(Ex);

                    }
                    return 0;
                }

                public void finished() {

                    this.interrupt();//sets flag

                }

            };

            CAPTURE_THREAD.begin();//executes thread

        } else if (option == 1) {
            SAVE.setEnabled(false);
            CAPTURE_THREAD = new PacketCaptThread() {

                public Object construct() {
                    OUTPUT_WINDOW.setText("\nNow Capturing on interface " + INDEX + "..."
                            + "\n--------------------------------------------------"
                            + "----------------------------------------------\n\n");

                    try {

                        CAPTOR = JpcapCaptor.openDevice(NET_INTERFACES[INDEX], 65535, false, 20);//opens new device interface
                        CAPTOR.setFilter("ip", true);
                        //filters ipv6 out

                        while (CaptStatus) {//while true

                            //CAPTOR.processPacket(1, new PacketCapt_PacketContents());//capture packets using concurrency
                            try {
                                Packet packet = CAPTOR.getPacket();
                                String format = "";

                                if (packet == null) {
                                    continue;
                                }
                                format = packet.toString();
                                format = format.replace("protocol", "");
                                format = format.replace("priority", "");
                                format = format.replace("hop", "");
                                format = format.replace("offset", "");
                                format = format.replace("ident", "");
                                format = format.replaceAll("\\(.*?\\)", "");

                                OUTPUT_WINDOW.append(
                                        format
                                        + "\n--------------------------------------------------"
                                        + "-----------------------------------------------\n\n");

                            } catch (Exception NullPointerException) {

                            }

                            // 
                        }

                        CAPTOR.close();
                        OUTPUT_WINDOW.append("\nCapturing Ended.....");

                        //closes the capturing process
                    } catch (Exception Ex) {

                        System.out.println(Ex);

                    }
                    return 0;
                }

                public void finished() {

                    this.interrupt();//sets flag

                }

            };

            CAPTURE_THREAD.begin();

        } else {
        }
    }

    public void loadDump() {
        String format = "%1$20s %2$20s %3$10s %4$25s %5$25s";//format output
        String lineHeading, line;
        lineHeading = String.format(format, "Source IP", "Dest IP", " Protocol", "SourceMAC", "DestMAC");
      try {
        JFileChooser fc = new JFileChooser(new File("c:\\"));//default directory
        int result = fc.showOpenDialog(null);//open a file dialog
        if (result == JFileChooser.APPROVE_OPTION) {

            file = fc.getSelectedFile();
            path = file.getAbsolutePath();//get file loctation
            //if (option == 0) {

            OUTPUT_WINDOW.setText("Loading dump.....\n"
                    + lineHeading + "\n");
           
                CAPTOR = JpcapCaptor.openFile(path);//open data dump at the obtained directory
                while (CaptStatus) {

                    Packet pkt = CAPTOR.getPacket();//create generic packet object
                    IPPacket IPpkt = (IPPacket) pkt;//convert the generic packet object to an IP packet
                    String mac = IPpkt.datalink.toString();//get data link layer inoformataion from the packet and convert the information into string format
                    String newMAC = mac.replaceAll("jpcap.packet.EthernetPacket@.*?\\s+", "");//format the content in the mac string
                    String[] MAC = newMAC.split("->", 2);//string formatting
                    String srcMAC = MAC[0];//string formatting
                    String temp = MAC[1];//string formatting
                    String[] dstMAC = temp.split(" ", 2);//string formatting

                    if (pkt == null || pkt == Packet.EOF) {//If the packet object is null or has reached EOF break the loop
                        break;
                    }
                    line = String.format(format, IPpkt.src_ip, IPpkt.dst_ip, IPpkt.protocol, srcMAC, dstMAC[0]);//append the content to the JTextArea
                    OUTPUT_WINDOW.append(line + "\n");
                }
                }
            } catch (Exception E) {

            }
            CAPTOR.close();//close the loading process
            CaptStatus = false;
        

    }

    public void Filter(String input) {
        String format = "%1$20s %2$20s %3$10s %4$25s %5$25s";
        String lineHeading, line;
        lineHeading = String.format(format, "Source IP", "Dest IP", " Protocol", "SourceMAC", "DestMAC");

        OUTPUT_WINDOW.setText("Loading dump.....\n"
                + lineHeading + "\n");
        try {
            CAPTOR = JpcapCaptor.openFile(path);
            while (CaptStatus) {

                Packet pkt = CAPTOR.getPacket();
                IPPacket IPpkt = (IPPacket) pkt;
                String mac = IPpkt.datalink.toString();
                String newMAC = mac.replaceAll("jpcap.packet.EthernetPacket@.*?\\s+", "");
                String[] MAC = newMAC.split("->", 2);
                String srcMAC = MAC[0];
                String temp = MAC[1];
                String[] dstMAC = temp.split(" ", 2);
                //System.out.println(String.valueOf(IPpkt.src_ip));
                if (IPpkt == null || IPpkt == Packet.EOF) {
                    break;
                }
                if (input.equals(IPpkt.src_ip.toString())) {//checks whether input equals the source IP address

                    //CAPTOR.setFilter(IPpkt.src_ip.toString(), true);
                    line = String.format(format, IPpkt.src_ip, IPpkt.dst_ip, IPpkt.protocol, srcMAC, dstMAC[0]);
                    OUTPUT_WINDOW.append(line + "\n");
                } else if (input.equals(IPpkt.dst_ip.toString())) {//checks whether input equals the dest IP address
                    //CAPTOR.setFilter(IPpkt.dst_ip.toString(), true);
                    line = String.format(format, IPpkt.src_ip, IPpkt.dst_ip, IPpkt.protocol, srcMAC, dstMAC[0]);
                    OUTPUT_WINDOW.append(line + "\n");
                } else if (input.equals(String.valueOf(IPpkt.protocol))) {//checks whether input equals the protocol
                    // CAPTOR.setFilter(String.valueOf(IPpkt.protocol),true);
                    line = String.format(format, IPpkt.src_ip, IPpkt.dst_ip, IPpkt.protocol, srcMAC, dstMAC[0]);
                    OUTPUT_WINDOW.append(line + "\n");
                } else if (input.equals(srcMAC)) {//checks whether input equals the source MAC address
                    // CAPTOR.setFilter(srcMAC, true);
                    line = String.format(format, IPpkt.src_ip, IPpkt.dst_ip, IPpkt.protocol, srcMAC, dstMAC[0]);
                    OUTPUT_WINDOW.append(line + "\n");
                } else if (input.equals(dstMAC[0])) {//checks whether input equals the dest MAC address
                    //CAPTOR.setFilter(dstMAC[0], true);
                    line = String.format(format, IPpkt.src_ip, IPpkt.dst_ip, IPpkt.protocol, srcMAC, dstMAC[0]);
                    OUTPUT_WINDOW.append(line + "\n");
                }
            }

        } catch (Exception E) {

        }
        CAPTOR.close();
        CaptStatus = false;

    }
    String synIP, ackIP, synIP2, ackIP2, synIP3, ackIP3 = "";

    public void tcpFilter() {
        TCPPacket tcpPktTemp = null;
        String[] synLine;

        String dt = null;
        int result;
        TCPPacket TCPpkt = null;
        int synCount = 0;
        int count = 0;
        int ackcount = 0;

        String format = "%1$20s %2$20s %3$20s ";//format output
        String lineHeading, line = null;
        lineHeading = String.format(format, "Source IP", "Dest IP", " Status");
        
        
        JFileChooser fc = new JFileChooser(new File("c:\\"));//default directory
        result = fc.showOpenDialog(null);//open a file dialog
        if (result == JFileChooser.APPROVE_OPTION) {

            file = fc.getSelectedFile();

            path = file.getAbsolutePath();//get file loctation
            //if (option == 0) {

            OUTPUT_WINDOW.setText("Loading dump.....\n"
                    + lineHeading + "\n");
            try {
                CAPTOR = JpcapCaptor.openFile(path);//open data dump at the obtained directory
                while (CaptStatus) {

                    Packet pkt = CAPTOR.getPacket();//create generic packet object

                    IPPacket IPpkt = (IPPacket) pkt;
                    if (IPpkt.protocol == 6) {
                        TCPpkt = (TCPPacket) pkt;//convert the generic packet object to an TCP packet

                        if (pkt == null || pkt == Packet.EOF) {//If the packet object is null or has reached EOF break the loop
                            break;
                        }

                        if (TCPpkt.offset == 0) {//why??

                            if (TCPpkt.syn && !TCPpkt.ack) {

                                line = String.format(format, TCPpkt.src_ip, TCPpkt.dst_ip, "SYN");//append the content to the JTextArea
                                OUTPUT_WINDOW.append(line + "\n");
                                synIP = TCPpkt.src_ip.toString();
                                count++;
                                synCount++;
                                pkt = CAPTOR.getPacket();//create generic packet object

                                IPpkt = (IPPacket) pkt;
                                if (IPpkt.protocol == 6) {
                                    TCPpkt = (TCPPacket) pkt;//convert the generic packet object to an TCP packet

                                    if (pkt == null || pkt == Packet.EOF) {//If the packet object is null or has reached EOF break the loop
                                        break;
                                    }
                                    if (TCPpkt.offset == 0) {
                                        if (TCPpkt.syn && !TCPpkt.ack) {
                                            line = String.format(format, TCPpkt.src_ip, TCPpkt.dst_ip, "SYN");//append the content to the JTextArea
                                            OUTPUT_WINDOW.append(line + "\n");
                                            synIP = TCPpkt.src_ip.toString();
                                            synCount++;
                                            count++;

                                        } else if (TCPpkt.syn && TCPpkt.ack && !TCPpkt.fin && !TCPpkt.rst && !TCPpkt.psh) {
                                            line = String.format(format, TCPpkt.src_ip, TCPpkt.dst_ip, "SYN-ACK");//append the content to the JTextArea
                                            OUTPUT_WINDOW.append(line + "\n");
                                            pkt = CAPTOR.getPacket();//create generic packet object

                                            IPpkt = (IPPacket) pkt;
                                            if (IPpkt.protocol == 6) {
                                                TCPpkt = (TCPPacket) pkt;//convert the generic packet object to an TCP packet

                                                if (pkt == null || pkt == Packet.EOF) {//If the packet object is null or has reached EOF break the loop
                                                    break;
                                                }
                                                if (TCPpkt.offset == 0) {
                                                    if (TCPpkt.syn && !TCPpkt.ack) {
                                                        line = String.format(format, TCPpkt.src_ip, TCPpkt.dst_ip, "SYN");//append the content to the JTextArea
                                                        OUTPUT_WINDOW.append(line + "\n");
                                                        synIP = TCPpkt.src_ip.toString();
                                                        count++;
                                                        synCount++;

                                                    } else if (TCPpkt.syn && TCPpkt.ack && !TCPpkt.fin && !TCPpkt.rst && !TCPpkt.psh) {
                                                        line = String.format(format, TCPpkt.src_ip, TCPpkt.dst_ip, "SYN-ACK");//append the content to the JTextArea
                                                        OUTPUT_WINDOW.append(line + "\n");

                                                    } else if (TCPpkt.ack && !TCPpkt.syn && !TCPpkt.rst && !TCPpkt.fin && !TCPpkt.psh) {
                                                        line = String.format(format, TCPpkt.src_ip, TCPpkt.dst_ip, "ESTABLISHED");//append the content to the JTextArea 
                                                        OUTPUT_WINDOW.append(line + "\n");
                                                        ackIP = TCPpkt.src_ip.toString();
                                                        if (synIP == ackIP) {
                                                            count--;
                                                        }

                                                        ackcount++;

                                                    }
                                                }

                                            }
                                        } else if (TCPpkt.ack && !TCPpkt.syn && !TCPpkt.rst && !TCPpkt.fin && !TCPpkt.psh) {
                                            line = String.format(format, TCPpkt.src_ip, TCPpkt.dst_ip, "ESTABLISHED");//append the content to the JTextArea 
                                            OUTPUT_WINDOW.append(line + "\n");

                                            ackcount++;
                                            pkt = CAPTOR.getPacket();//create generic packet object

                                            IPpkt = (IPPacket) pkt;
                                            if (IPpkt.protocol == 6) {
                                                TCPpkt = (TCPPacket) pkt;//convert the generic packet object to an TCP packet

                                                if (pkt == null || pkt == Packet.EOF) {//If the packet object is null or has reached EOF break the loop
                                                    break;
                                                }
                                                if (TCPpkt.offset == 0) {
                                                    if (TCPpkt.syn && !TCPpkt.ack) {
                                                        line = String.format(format, TCPpkt.src_ip, TCPpkt.dst_ip, "SYN");//append the content to the JTextArea
                                                        OUTPUT_WINDOW.append(line + "\n");
                                                        synIP = TCPpkt.src_ip.toString();
                                                        count++;
                                                        synCount++;

                                                    } else if (TCPpkt.syn && TCPpkt.ack && !TCPpkt.fin && !TCPpkt.rst && !TCPpkt.psh) {
                                                        line = String.format(format, TCPpkt.src_ip, TCPpkt.dst_ip, "SYN-ACK");//append the content to the JTextArea
                                                        OUTPUT_WINDOW.append(line + "\n");
                                                        pkt = CAPTOR.getPacket();//create generic packet object

                                                        IPpkt = (IPPacket) pkt;
                                                        if (IPpkt.protocol == 6) {
                                                            TCPpkt = (TCPPacket) pkt;//convert the generic packet object to an TCP packet

                                                            if (pkt == null || pkt == Packet.EOF) {//If the packet object is null or has reached EOF break the loop
                                                                break;
                                                            }
                                                            if (TCPpkt.offset == 0) {
                                                                if (TCPpkt.syn && !TCPpkt.ack) {
                                                                    line = String.format(format, TCPpkt.src_ip, TCPpkt.dst_ip, "SYN");//append the content to the JTextArea
                                                                    OUTPUT_WINDOW.append(line + "\n");
                                                                    synIP = TCPpkt.src_ip.toString();
                                                                    count++;
                                                                    synCount++;

                                                                } else if (TCPpkt.syn && TCPpkt.ack && !TCPpkt.fin && !TCPpkt.rst && !TCPpkt.psh) {
                                                                    line = String.format(format, TCPpkt.src_ip, TCPpkt.dst_ip, "SYN-ACK");//append the content to the JTextArea
                                                                    OUTPUT_WINDOW.append(line + "\n");

                                                                } else if (TCPpkt.ack && !TCPpkt.syn && !TCPpkt.rst && !TCPpkt.fin && !TCPpkt.psh) {
                                                                    line = String.format(format, TCPpkt.src_ip, TCPpkt.dst_ip, "ESTABLISHED");//append the content to the JTextArea
                                                                    OUTPUT_WINDOW.append(line + "\n");
                                                                    ackIP = TCPpkt.src_ip.toString();
                                                                    if (synIP == ackIP) {
                                                                        count--;
                                                                    }

                                                                    ackcount++;

                                                                }
                                                            }

                                                        }
                                                    } else if (TCPpkt.ack && !TCPpkt.syn && !TCPpkt.rst && !TCPpkt.fin && !TCPpkt.psh) {
                                                        line = String.format(format, TCPpkt.src_ip, TCPpkt.dst_ip, "ESTABLISHED");//append the content to the JTextArea 
                                                        OUTPUT_WINDOW.append(line + "\n");
                                                        ackIP = TCPpkt.src_ip.toString();
                                                        if (synIP == ackIP) {
                                                            count--;
                                                        }

                                                        ackcount++;

                                                    }
                                                }

                                            }

                                        }
                                    }
                                }

                            } else if (TCPpkt.syn && TCPpkt.ack && !TCPpkt.fin && !TCPpkt.rst && !TCPpkt.psh) {
                                line = String.format(format, TCPpkt.src_ip, TCPpkt.dst_ip, "SYN-ACK");//append the content to the JTextArea 
                                OUTPUT_WINDOW.append(line + "\n");
                                pkt = CAPTOR.getPacket();//create generic packet object
                                IPpkt = (IPPacket) pkt;
                                if (IPpkt.protocol == 6) {
                                    TCPpkt = (TCPPacket) pkt;//convert the generic packet object to an TCP packet

                                    if (pkt == null || pkt == Packet.EOF) {//If the packet object is null or has reached EOF break the loop
                                        break;
                                    }
                                    if (TCPpkt.offset == 0) {
                                        if (TCPpkt.syn && !TCPpkt.ack) {
                                            line = String.format(format, TCPpkt.src_ip, TCPpkt.dst_ip, "SYN");//append the content to the JTextArea
                                            OUTPUT_WINDOW.append(line + "\n");
                                            synIP = TCPpkt.src_ip.toString();
                                            count++;
                                            synCount++;

                                        } else if (TCPpkt.syn && TCPpkt.ack && !TCPpkt.fin && !TCPpkt.rst && !TCPpkt.psh) {
                                            line = String.format(format, TCPpkt.src_ip, TCPpkt.dst_ip, "SYN-ACK");//append the content to the JTextArea
                                            OUTPUT_WINDOW.append(line + "\n");
                                            pkt = CAPTOR.getPacket();//create generic packet object

                                            IPpkt = (IPPacket) pkt;
                                            if (IPpkt.protocol == 6) {
                                                TCPpkt = (TCPPacket) pkt;//convert the generic packet object to an TCP packet

                                                if (pkt == null || pkt == Packet.EOF) {//If the packet object is null or has reached EOF break the loop
                                                    break;
                                                }
                                                if (TCPpkt.offset == 0) {
                                                    if (TCPpkt.syn && !TCPpkt.ack) {
                                                        line = String.format(format, TCPpkt.src_ip, TCPpkt.dst_ip, "SYN");//append the content to the JTextArea
                                                        OUTPUT_WINDOW.append(line + "\n");
                                                        synIP = TCPpkt.src_ip.toString();
                                                        synCount++;
                                                        count++;

                                                    } else if (TCPpkt.syn && TCPpkt.ack && !TCPpkt.fin && !TCPpkt.rst && !TCPpkt.psh) {
                                                        line = String.format(format, TCPpkt.src_ip, TCPpkt.dst_ip, "SYN-ACK");//append the content to the JTextArea
                                                        OUTPUT_WINDOW.append(line + "\n");

                                                    } else if (TCPpkt.ack && !TCPpkt.syn && !TCPpkt.rst && !TCPpkt.fin && !TCPpkt.psh) {
                                                        line = String.format(format, TCPpkt.src_ip, TCPpkt.dst_ip, "ESTABLISHED");//append the content to the JTextArea 
                                                        OUTPUT_WINDOW.append(line + "\n");
                                                        ackIP = TCPpkt.src_ip.toString();
                                                        if (synIP == ackIP) {
                                                            count--;
                                                        }

                                                        ackcount++;

                                                    }
                                                }

                                            }

                                        } else if (TCPpkt.ack && !TCPpkt.syn && !TCPpkt.rst && !TCPpkt.fin && !TCPpkt.psh) {
                                            line = String.format(format, TCPpkt.src_ip, TCPpkt.dst_ip, "ESTABLISHED");//append the content to the JTextArea 
                                            OUTPUT_WINDOW.append(line + "\n");

                                            ackcount++;
                                            pkt = CAPTOR.getPacket();//create generic packet object

                                            IPpkt = (IPPacket) pkt;
                                            if (IPpkt.protocol == 6) {
                                                TCPpkt = (TCPPacket) pkt;//convert the generic packet object to an TCP packet

                                                if (pkt == null || pkt == Packet.EOF) {//If the packet object is null or has reached EOF break the loop
                                                    break;
                                                }
                                                if (TCPpkt.offset == 0) {
                                                    if (TCPpkt.syn && !TCPpkt.ack) {
                                                        line = String.format(format, TCPpkt.src_ip, TCPpkt.dst_ip, "SYN");//append the content to the JTextArea
                                                        OUTPUT_WINDOW.append(line + "\n");
                                                        synIP = TCPpkt.src_ip.toString();
                                                        count++;
                                                        synCount++;

                                                    } else if (TCPpkt.syn && TCPpkt.ack && !TCPpkt.fin && !TCPpkt.rst && !TCPpkt.psh) {
                                                        line = String.format(format, TCPpkt.src_ip, TCPpkt.dst_ip, "SYN-ACK");//append the content to the JTextArea
                                                        OUTPUT_WINDOW.append(line + "\n");

                                                    } else if (TCPpkt.ack && !TCPpkt.syn && !TCPpkt.rst && !TCPpkt.fin && !TCPpkt.psh) {
                                                        line = String.format(format, TCPpkt.src_ip, TCPpkt.dst_ip, "ESTABLISHED");//append the content to the JTextArea 
                                                        OUTPUT_WINDOW.append(line + "\n");
                                                        ackIP = TCPpkt.src_ip.toString();
                                                        if (synIP == ackIP) {
                                                            count--;
                                                        }

                                                        ackcount++;

                                                    }
                                                }

                                            }
                                        }
                                    }

                                }

                            } else if (TCPpkt.ack && !TCPpkt.syn && !TCPpkt.rst && !TCPpkt.fin && !TCPpkt.psh) {
                                line = String.format(format, TCPpkt.src_ip, TCPpkt.dst_ip, "ESTABLISHED");//append the content to the JTextArea 
                                OUTPUT_WINDOW.append(line + "\n");
                            }

                        }

                    }

                }
            } catch (Exception E) {

            }
            CAPTOR.close();//close the loading process
            CaptStatus = false;
            int diff = synCount - ackcount;
            if (diff >= 100) {

                OUTPUT_WINDOW.append("System at risk of TCP SYN Flood");
                if (count > 100) {

                    sendMail(synIP);

                }

            } else {
                OUTPUT_WINDOW.append("No SYN-Flood Risk");
            }

        }

    }

    public void sendMail(String IP) {

        String to = "bwimad@gmail.com";
        String from = "bhavinmeheta94@gmail.com";
        String password = "DdA2*H&tB";
        Properties properties = System.getProperties();

        // Setup mail server
        properties.put("mail.smtp.starttls.enable", true);
        properties.put("mail.smtp.user", to);
        properties.put("mail.smtp.auth", true);
        properties.put("mail.smtp.host", "smtp.gmail.com");
        properties.put("mail.smtp.port", "587");
        properties.put("mail.smtp.ssl.trust", "smtp.gmail.com");

        // Get the default Session object.
        Session session = Session.getInstance(properties,
                new javax.mail.Authenticator() {
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(from, password);
            }
        });

        try {

            Message msg = new MimeMessage(session);//creates new email object
            msg.setFrom(new InternetAddress(from));//specify sender
            msg.setRecipients(Message.RecipientType.TO, InternetAddress.parse(to));//specify reciever
            msg.setSubject("System at SYN-Flood Attack Risk");//subject of the email
            msg.setText("Dear User,"
                    + "\n\nYour system has recieved at unsual amount of TCP SYN request from address" + IP); //content of the email

            Transport.send(msg);//sends email

            OUTPUT_WINDOW.append("\nEmail Sent To Vulnerable System\n");

        } catch (MessagingException e) {
            // throw new RuntimeException(e);
            System.out.println(e);
        }
    }

    public void visited() {
        
        try {
        JTextArea temp = new JTextArea();
        JFileChooser fc = new JFileChooser(new File("c:\\"));//default directory
        int result = fc.showOpenDialog(null);//open a file dialog
        if (result == JFileChooser.APPROVE_OPTION) {

            file = fc.getSelectedFile();
            path = file.getAbsolutePath();//get file loctation
            //if (option == 0) {
            String address = "";
            String format = "";
            String Time = "";

           
                CAPTOR = JpcapCaptor.openFile(path);//open data dump at the obtained directory
                while (CaptStatus) {

                    Packet pkt = CAPTOR.getPacket();//create generic packet object

                    IPPacket IPpkt = (IPPacket) pkt;
                    if (IPpkt.protocol == 6) {
                        TCPPacket TCPpkt = (TCPPacket) pkt;//convert the generic packet object to an TCP packet

                        if (pkt == null || pkt == Packet.EOF) {//If the packet object is null or has reached EOF break the loop
                            break;
                        }
                        int srcport = TCPpkt.src_port;
                        int destPort = TCPpkt.dst_port;

                        if (srcport == 80 || destPort == 80) {//filter http straffic
                            byte[] b = TCPpkt.data;

                            format = new String(b, "UTF-8");//byte to string conversion
                            

                            temp.append(format + "\n ");

                        }

                    }

                    Set<String> addressSet = new HashSet<String>(Arrays.asList(temp.getText().split("\n")));

                    //Displays information regarding visited sites
                    OUTPUT_WINDOW.setText("Visited Sites :" + "\n");
                    for (String entry : addressSet) {

                        if (((entry.contains(("Referer:"))))) {

                            address = entry.replaceAll("Referer:", "");
                            OUTPUT_WINDOW.append(address + " " + "\n");

                        }
                        if (((entry.contains(("Location:"))))) {

                            address = entry.replaceAll("Location:", "");
                            OUTPUT_WINDOW.append(address + " " + "\n");

                        }

                        if ((entry.contains(("Date:")))) {
                            address = entry.replaceAll("Date:", "");
                            OUTPUT_WINDOW.append(address + "\n");

                        }

                    }

                }

                CAPTOR.close();
                CaptStatus = false;
        }

            } catch (Exception E) {

            }
        

    }

    public void DisableButtons() {

        CAPTURE.setEnabled(false);
        STOP.setEnabled(false);
        SELECT.setEnabled(false);

        SAVE.setEnabled(false);
    }

    public void EnableButtons() {

        CAPTURE.setEnabled(true);
        STOP.setEnabled(true);

    }

}
