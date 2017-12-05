package PasswordCracker;

import java.util.concurrent.*;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.List;
import java.util.ArrayList;

public class PasswordCrackerMain {

    public static void main(String args[]) throws Exception{
        if (args.length < 4) {
            System.out.println("Usage: PasswordCrackerMain numThreads passwordLength isEarlyTermination encryptedPassword");
            return;
        }
        
        int numThreads = Integer.parseInt(args[0]);
        int passwordLength = Integer.parseInt(args[1]);
        boolean isEarlyTermination = Boolean.parseBoolean(args[2]);
        String encryptedPassword = args[3];
        
        ExecutorService workerPool = Executors.newFixedThreadPool(numThreads);
        PasswordFuture passwordFuture = new PasswordFuture();
        PasswordCrackerConsts consts = new PasswordCrackerConsts(numThreads, passwordLength, encryptedPassword);

		/*
         * Create PasswordCrackerTask and use executor service to run in a separate thread
		*/
        for (int i = 0; i < numThreads; i++) {
            PasswordCrackerTask task = new PasswordCrackerTask(i, isEarlyTermination, consts, passwordFuture);
            workerPool.submit(task); 
        }

        workerPool.shutdown();

        try {
            System.out.println("20142028");
            System.out.println(numThreads);
            System.out.println(passwordLength);
            System.out.println(isEarlyTermination);
            System.out.println(encryptedPassword);
            System.out.println(passwordFuture.get());
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            workerPool.shutdown();
        }
    }
}

class PasswordFuture implements Future<String> {
    String result = null;
    Lock lock = new ReentrantLock();
    Condition resultSet = lock.newCondition(); 

    public void set(String result) {
        lock.lock();
        try {
        this.result = result;
        resultSet.signalAll();

        } finally {
            lock.unlock();
        }
    }

    /*  ### get ###
     *  if result is ready, return it.
     *  if not, wait on the conditional variable.
     */
    @Override
    public String get() throws InterruptedException, ExecutionException {
        lock.lock();
        try {
            while(result == null) {
               resultSet.await(); 
            }
            return result;
        } finally {
            lock.unlock();
        }  
    }

    /*  ### isDone ###
     *  returns true if result is set
     */
    @Override
    public boolean isDone() {
        return result != null;
    }

    @Override
    public boolean cancel(boolean mayInterruptIfRunning) {
        return false;
    }
    
    @Override
    public boolean isCancelled() {
        return false;
    }

    @Override
    public String get(long timeout, TimeUnit unit) throws InterruptedException, ExecutionException, TimeoutException {
        // no need to implement this. We don't use this...
        return null;
    }
}
