import React from "react";
import { FiSearch } from "react-icons/fi";

const SearchComponent = ({ searchQuery, setSearchQuery }) => {
    const handleSearchChange = (event) => {
        setSearchQuery(event.target.value);
    };

    return (
        <div className="flex justify-end mb-4 mr-9 pr-8">
            <div className="relative items-center justify-around gap-2 rounded-full bg-white px-3 py-3 shadow-xl shadow-shadow-500 dark:!bg-navy-800 dark:shadow-none md:flex-grow-0 md:gap-1">
                <div className="flex h-full items-center w-full rounded-full bg-lightPrimary text-navy-700 dark:bg-navy-900 dark:text-white">
                    <p className="pl-5 pr-5 text-xl">
                        <FiSearch className="h-8 w-6 text-gray-500 dark:text-white" />
                    </p>
                    <input
                        type="text"
                        placeholder="Search..."
                        className="block h-full w-full rounded-full bg-lightPrimary text-lg font-medium text-navy-700 outline-none placeholder:!text-gray-400 dark:bg-navy-900 dark:text-white dark:placeholder:!text-white sm:w-fit"
                        value={searchQuery}
                        onChange={handleSearchChange}
                    />
                </div>
            </div>
        </div>






    );
};

export default SearchComponent;
