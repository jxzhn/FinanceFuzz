// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

contract GasConsumingFallback {
    uint256 count = 0;
    fallback() external payable {
        ++count;
    }
}