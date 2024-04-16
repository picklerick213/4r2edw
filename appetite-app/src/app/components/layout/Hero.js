import Image from "next/image";
import Right from "../icons/Right";
import Header from "./Header";

export default function Hero(){

    return(

        <section>
            <Header />
            <div className="hero max-w-4xl mx-auto p-4 mt-6 z-40">
                <div className="py-7">
                    <h1 className="text-4xl font-semibold leading-12">
                        "Satisfy Your Cravings, <span className="text-primary">One Click Away!</span>"
                    </h1>
                    <p className="my-4 text-gray-500"> 
                        "Leveraging Technology to Showcase and Preserve 
                        Local Culinary Heritage"
                        </p>

                    <div className="flex gap-4 text-sm">
                        <button className="flex justify-center bg-primary uppercase items-center 
                        flex gap-2 text-white px-4 py-2 rounded-full hover:bg-gray-300 transition-all hover:shadow-2xl hover:shadow-black-300 hover:text-black ">
                            Order Now
                            <Right />
                        </button>
                        <button className="flex items-center border-0 gap-2 py-2 text-gray-600 hover:scale-110 transition-all">
                            Learn More
                            <Right />
                        </button>
                    </div>
                </div>
        
                <div className="relative z-0 ">
                    <Image src={'/pancit bihon.png'} layout={'fill'}
                    objectFit={'contain'} alt={'pancit'}/>
                </div>
            </div>
        </section>
    );
}

