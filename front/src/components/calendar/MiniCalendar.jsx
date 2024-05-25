import React, { useState } from "react";
import Calendar from "react-calendar";
import Card from "components/card";
import "react-calendar/dist/Calendar.css";
import { MdChevronLeft, MdChevronRight } from "react-icons/md";
import "assets/css/MiniCalendar.css";

const MiniCalendar = (props) => {
  const handleDateChange = (value) => {
    // If the length of the value array is 2, it means both start and end dates are selected
    if (value.length === 2) {
      props.sendDates(value);
    }
  };

  return (
    <div>
      <Card extra="flex w-full h-full flex-col px-3 py-3">
        <Calendar
          selectRange
          onChange={handleDateChange}
          prevLabel={<MdChevronLeft className="ml-1 h-6 w-6 " />}
          nextLabel={<MdChevronRight className="ml-1 h-6 w-6 " />}
          view={"month"}
        />
      </Card>
    </div>
  );
};

export default MiniCalendar;
