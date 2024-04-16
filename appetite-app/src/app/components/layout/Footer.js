import Link from "next/link";
import { RiFacebookCircleFill } from "react-icons/ri";
import { RiInstagramFill } from "react-icons/ri";
import { RiTwitterXFill } from "react-icons/ri";
import { RiTiktokLine } from "react-icons/ri";
import SectionHeaders from "@/app/components/layout/SectionHeaders";

export default function Footer(){
    return(
        <section>
                <div className="max-w-4xl mx-auto border-t ">
                  <div className="text-center py-20"> 
                    <SectionHeaders mainHeader={'CONTACT US'} />
                    <SectionHeaders subHeader={"let's stay connected"}/>
                  </div>
                </div>
                
              <div className="bg-primary p-5">
                <div className=" p-8  items-center flex justify-evenly">
                  <div className="hover:underline text-white">
                    <Link className=" font-semibold  justify-center" href="/">
                      <span className='text-1xl text-white italic'>APP</span>
                      <span className='text-2xl  text-white '> ETITE</span>
                    </Link>
                  </div>
                  <div>
                    <div className="flex gap-4 text-2xl my-5 text-white">
                      <Link className="hover:scale-110 transition-all" href={''}><RiFacebookCircleFill /></Link>

                      <Link className="hover:scale-110 transition-all" href={''}><RiInstagramFill /></Link>

                      <Link className="hover:scale-110 transition-all" href={''}><RiTwitterXFill /></Link>

                      <Link className="hover:scale-110 transition-all" href={''}><RiTiktokLine /></Link>
                    </div>
                  </div>

                  <div>
                    <div className="" id="contact">
                      <a  className="text-1xl italic text-white" 
                      href="tel:+63 408 1914 007">
                        +63 408 1914 007
                      </a>
                    </div>
                  </div>
            
            <div className="bg-secondary p-3 rounded-lg text-white hover:scale-110 transition-all">
                <Link  
                    href={'/menu'}>Order now!
                </Link>
            </div>
                    
                
                
                </div>
                </div>
                    <div className="text-center text-sm text-white bg-secondary p-6">
                      &copy; 2024 All Rigts Reserved
                    </div>
        </section>
    )
}