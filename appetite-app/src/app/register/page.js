"use client";
import Image from "next/image";
import Link from "next/link";
import {useState} from "react";
import {signIn} from "next-auth/react";

export default function RegisterPage() {
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [creatingUser, setCreatingUser] = useState(false);
    const [userCreated, setUserCreated] = useState(false);
    const [error, setError] = useState(false);
    async function handleFromSubmit(ev) {
    ev.preventDefault();
    setCreatingUser(true);
    setError(false);
    setCreatingUser(false);
    const response = await fetch('.//api/register', {
        method: 'POST',
        body: JSON.stringify({email, password}),
        headers: {'Content-Type': 'application/json'},
    });
    if (response.ok){
        setUserCreated(true);
    }
    else{
        setError(true);
    }
    setCreatingUser(false);
        }
    return(
        <section>
            <div className="mt-[5.5rem] max-w-5xl mx-auto p-4 mb-10">
                <div className="">
                    <h1 className="text-center text-primary text-4xl mb-4 mt-10">
                    Register
                    </h1>
                    {userCreated && (
                        <div className="my=4 text-center">
                            Account Created. Now you can {''} 
                            <Link className="underline" href={'/login'}>
                                login &raquo;
                            </Link>
                        </div>
                    )}
                    <form className="block max-w-xs mx-auto mt-6" onSubmit={handleFromSubmit}>
                        <input type="email" placeholder="email" value={email} 
                        disabled={creatingUser}
                        onChange={ev => setEmail (ev.target.value)} />
                        <input type="password" placeholder="password" value={password}
                        disabled={creatingUser}
                        onChange={ev => setPassword(ev.target.value)} />
                        <button className="hover:bg-gray-300 transition-all hover:shadow-2xl hover:shadow-black-300 hover:text-black" type="submit" disabled={creatingUser}>
                            Register
                        </button>

                        <div className="my-4 text-center text-gray-500">
                            or login with provider
                        </div>
                        <button 
                        onClick={ ()=> signIn('google', {callbackUrl: '/'})} 
                        className="flex gap-4 justify-center whitespace-nowrap hover:scale-110 transition-all">
                        <Image src={'/google.png'} alt={''} width={24} height={24}/>
                            Login with google
                        </button>
                        <div className="text-center my-4 text-gray-500 border-t pt-4 ">
                            <div className="flex justify-center text-sm gap-1">
                                <div>Existing Account?</div>
                                <div><Link className="text-gray-500 hover:text-primary hover:underline" href={'/login'}>Login here</Link></div>
                            </div>
                        </div>
                    </form>
                </div>
            </div>

        </section>
    );
}