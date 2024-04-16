'use client';
import {signIn} from "next-auth/react";
import Image from "next/image";
import Link from "next/link";
import { useState } from "react";

export default function LoginPage(){
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [loginInProgress, setLoginInProgresss] = useState(false);
    

    async function handleFormSubmit(ev) {
        ev.preventDefault();
        setLoginInProgresss(true);

        await signIn('credentials' , {email, password, callbackUrl: '/'});
        
        setLoginInProgresss(false);
    }


    return(
        <section >
            <div className="mt-[5.5rem] max-w-5xl mx-auto p-4 mb-10">
                
                <div className=" rounded-2xl">
                    <h1 className="text-center text-primary text-4xl mb-4 mt-10">
                        Login
                    </h1>
                <div className="">
                        <form className="max-w-xs mx-auto mt-6" onSubmit={handleFormSubmit}>
                        <input type="email" name="email" placeholder="email" value={email} 
                            disabled={loginInProgress}
                            onChange={ev => setEmail (ev.target.value)} />
                        <input type="password" name="password" placeholder="password" value={password}
                            disabled={loginInProgress}
                            onChange={ev => setPassword(ev.target.value)} />
                            <button disabled={loginInProgress} 
                            className="hover:bg-gray-300 transition-all hover:shadow-2xl 
                            hover:shadow-black-300 hover:text-black" type="submit">Login</button>
                            
                            <div className="my-4 text-center text-gray-500">
                                or login with provider
                            </div>
                            <button type="button" onClick={ ()=> signIn('google', {callbackUrl: '/'})} 
                            className="flex gap-4 justify-center whitespace-nowrap hover:scale-110 transition-all">
                            <Image src={'/google.png'} alt={''} width={24} height={24}/>
                                Login with google
                            </button>
                            <div className="text-center my-4 text-gray-500 border-t pt-4 ">
                                <div className="flex justify-center gap-1 text-sm">
                                    <div>New user? </div>
                                    <div><Link className="text-gray-500 hover:text-primary hover:underline" href={'/register'}> Create an Account</Link></div>
                                </div>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </section>
    );
}