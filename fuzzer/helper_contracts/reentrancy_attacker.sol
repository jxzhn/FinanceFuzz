// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

contract ReentrancyAttacker {
    // need fuzzer to fill input data
    fallback(bytes calldata input) external payable returns (bytes memory output) {
        if (input.length == 0) {
            output = '';
        } else {
            (, output) = msg.sender.call(input);
        }
    }
}
