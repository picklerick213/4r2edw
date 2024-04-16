'use client';
import {signOut, useSession} from "next-auth/react";
import Link from "next/link";
import { useContext, useState } from "react";
import { CartContext } from "../AppContext";
import Cart from "@/app/components/icons/Cart";
import Bars2 from "@/app/components/icons/Bars2";
import UserImage from "./UserImage";

export default function Header(){
  const session = useSession();
    const status = session?.status;
    const userData = session.data?.user;
    const {cartProducts} = useContext(CartContext);
    let userName = userData?.name || userData?.email;
    const [mobileNavOpen, setMobileNavOpen] = useState(false);
    if (userName && userName.includes(' ')){
      userName = userName.split(' ')[0];
    }

    function AuthLinks ({status, userName}){
      if (status === 'authenticated') {
        return (
          <>
            <Link href={'/profile'} className="whitespace-nowrap hover:scale-110 transition-all"> <UserImage/> {userName}</Link>
           
            <Link
              onClick={() => signOut({callbackUrl: '/login'})} 
              className='text-white px-8 py-1.5 text-white px-6 py-2 hover:scale-110 transition-all' href={''}>
              Logout
            </Link>
          </>
        );
      }
      if (status === 'unauthenticated') {
        return (
          <>
            <Link className="hover:scale-110 transition-all" href="/login">Login</Link>
            <Link href={'/register'} className='text-white px-6 py-2 hover:scale-110 transition-all'>
              Register
            </Link>
          </>
        );
      }
    }
    return (
        <header className="sticky top-0 z-40">
          <div className="flex md:hidden justify-between bg-primary items-center max-w-4xl mx-auto p-2">
              <Link href={'/cart'} className="relative cartIcon"> 
                  <Cart />
                    {cartProducts?.length > 0 && (
                      <span className="absolute -top-2.5 -right-3 bg-gray-300 text-black text-xs py-1 px-1 rounded-full leading-3">
                        {cartProducts.length}
                      </span> 
                    )}
              </Link> 
            <Link className=" font-semibold  justify-center" href="/">
                <span className='text-base text-white italic'>APP</span>
                <span className='text-sm text-white '> ETITE</span>
            </Link>
            <div className="flex gap-2 items-center">
              <div className="gap-2 flex items-center">
              <button 
              className="p-1 barsIcon border-0"
              onClick={() => setMobileNavOpen(prev => !prev)}>
                <Bars2 />
              </button>   
              </div>
            </div>
          </div>
          {mobileNavOpen && (
              <div
                onClick={() => setMobileNavOpen(false)}
                className="md:hidden z-40 p-4 bg-gray-200 rounded-lg mt-1 flex flex-col gap-2 text-center">
                  <Link className="hover:scale-110 transition-all" href={'/'}>Home </Link>
                  <Link className="hover:scale-110 transition-all" href={'/menu'}>Menu</Link>
                  <Link className="hover:scale-110 transition-all" href={'/#contact'}>Contact</Link>
                  <AuthLinks status={status} userName={userName} />
             </div>
            )}

         

          <div className="hidden md:block">
            <div className="flex items-center justify-center justify-evenly px-2 py-0.3 bg-primary ">
              <Link className=" font-semibold  justify-center" href="/">
                <span className='text-base text-white italic'>APP</span>
                <span className='text-sm text-white '> ETITE</span>
              </Link>
            </div>
            <div className="flex bg-secondary max-w-auto justify-evenly flex gap-8">
              <nav className='flex  gap-8 justify-center items-center text-sm text-white  p-2.3'>
                <Link className="hover:scale-110 transition-all" href={'/'}>Home </Link>
                <Link className="hover:scale-110 transition-all" href={'/menu'}>Menu</Link>
                <Link className="hover:scale-110 transition-all" href={'/#contact'}>Contact</Link>
                <p className="text-xl	">|</p>
                  <div className='flex items-center text-sm text-white font-semibold'>
                    <AuthLinks status={status} userName={userName}/>
                      <div className="gap-2 flex items-center">
                        <p className="text-xl">|</p>
                        <Link href={'/cart'} className="relative cartIcon"> 
                            <Cart />
                              {cartProducts?.length > 0 && (
                                <span className="absolute -top-2.5 -right-3 bg-gray-300 text-black text-xs py-1 px-1 rounded-full leading-3">
                                  {cartProducts.length}
                                </span> 
                              )}
                        </Link>  
                      </div>
                  </div>
                </nav>
            </div>
          </div>
      </header>
    );
}
