import { columnsDataColumns } from "views/documents/variables/columnsData";
import GwLOTable from "./components/GwLOTable";




const Center = (props) => {
 
  return (

    <>
<GwLOTable
  center={props.center}
  columnsData={columnsDataColumns}
/>
</>

  );
};

export default Center;
