import { useLocation } from "react-router-dom";
import DocumentInfoTable from "./components/documentInfoTable";

const DocInfo = () => {
  const location=useLocation();
  const id = location.state.prop;
  return (
    <div className="flex w-full flex-col gap-5">
          <DocumentInfoTable id={id}/>
    </div>
  );
};

export default DocInfo;