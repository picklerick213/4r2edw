export default function SectionHeaders({subHeader,mainHeader}) {
    return (
      <>
      <h1 className="text-primary font-bold text-3xl  italic">
          {mainHeader}
        </h1>
        <h2 className="uppercase text-gray-500 font-semibold leading-4">
          {subHeader}
        </h2>
      </>
    );
  }