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
/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */




/**
 *
 * @author SHADOW
 */
public abstract class PacketCaptThread {

    private Object val;
    

    private static class ThreadVariable {

        private Thread thread;

        ThreadVariable(Thread t) {
            thread = t;

        }

        synchronized Thread get() {//creates synnchronized method get which returns thread

            return thread;
        }

        synchronized void clear() {//creates synnchronized method clear which sets the thread to null

            thread = null;

        }

    }

    private ThreadVariable threadVariable;//creating variable of ThreadVariable Class

    protected synchronized Object getVal() {//creates synnchronized method getVal which returns object val

        return val;

    }

    private synchronized void setVal(Object a) {//creates synnchronized method getVal which equates object val to object a

        val = a;

    }

    public abstract Object construct();//creates new abstract object

    public void ended() {//creates method ended
    }

    public void interrupt() {//method interrupt that implements get and clear 

        Thread b = threadVariable.get();
        if (b != null) {
            b.interrupt();//set interrupted flag set
        }
        threadVariable.clear();//set the instance to null

    }

    public Object get() {

        while (true) {

            Thread b = threadVariable.get();//get thread

            if (b == null) {//if thread is null return val
                return getVal();
            }

            try {

                b.join();//waits for the thread to die

            } catch (InterruptedException ex) {

                Thread.currentThread().interrupt();//keeps state
                return null;

            }

        }

    }

    public PacketCaptThread() {//contains the runnable threads

        final Runnable runFinished = new Runnable() {

            public void run() {

                ended();

            }
        };
        Runnable runConstruct = new Runnable() {

            public void run() {

                try {

                    setVal(construct());

                } finally {

                    threadVariable.clear();//clears thread

                }

            }

        };

        Thread b = new Thread(runConstruct);//new runnable thread
        threadVariable = new ThreadVariable(b);//assignes the runnable thread to the ThreadVariable instance

    }

    public void begin() {//intitaes thread execution

        Thread b = threadVariable.get();
        if (b != null) {
            b.start();
        }

    }

}

