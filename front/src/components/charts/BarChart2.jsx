import React from 'react';
import Chart from 'react-apexcharts';

class BarChart extends React.Component {
  render() {
    const { chartData, chartOptions } = this.props;
    return (
      <div className="bar-chart">
        <Chart
          options={chartOptions}
          series={chartData}
          type="bar"
          height="350" // Or any other height as needed
          // Remove width property if you want it to be 100% of the container
        />
      </div>
    );
  }
}

export default BarChart;
