/*
 * ===== SmartInject Injection Details =====
 * Function      : drawColors
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external callback to referralAddress before pixel state updates are complete. The vulnerability requires multiple transactions to exploit:
 * 
 * 1. **Transaction 1**: Attacker calls drawColors with their malicious contract as referralAddress to establish the callback relationship
 * 2. **Transaction 2**: Attacker calls drawColors again, triggering the callback during pixel state updates
 * 3. **During Callback**: The malicious contract can re-enter drawColors while pixel state is inconsistent (color, times, price updated but owner not yet set)
 * 
 * The vulnerability exploits the fact that:
 * - Pixel pricing depends on pixels[pixelIdx].times and previous owner
 * - The callback occurs after some state updates but before owner is set
 * - Multiple transactions are needed to set up the callback relationship and then exploit it
 * - The attacker can manipulate pixel ownership and pricing through reentrancy during the vulnerable window
 * 
 * This creates a realistic multi-transaction exploitation scenario where the attacker must first establish the callback relationship, then exploit the state inconsistency in subsequent transactions.
 */
pragma solidity ^0.4.18;

library SafeMath {
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a * b;
        assert(a == 0 || c / a == b);
        return c;
    }

    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a / b;
        return c;
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        assert(b <= a);
        return a - b;
        }

    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        assert(c >= a);
        return c;
    }
}

// Declare the missing interface to resolve compilation error
interface IPixelCallback {
    function onPixelUpdate(uint256 pixelIdx, uint256 color, uint256 price) external;
}

contract Ownable {
    address public owner;
    address public wallet;

    constructor() internal {
        owner = msg.sender;
        wallet = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }
}

contract EthColorAccount {
    using SafeMath for uint256;

    struct Account {
        uint256 balance;
        address referrer;
    }

    mapping (address => Account) accounts;

    event Withdraw(address indexed withdrawAddress, uint256 withdrawValue);
    event Transfer(address indexed addressFrom, address indexed addressTo, uint256 value, uint256 pixelId);

    // Check account detail
    function getAccountBalance(address userAddress) constant public returns (uint256) {
        return accounts[userAddress].balance;
    }
    function getAccountReferrer(address userAddress) constant public returns (address) {
        return accounts[userAddress].referrer;
    }

    // To withdraw your account balance from this contract.
    function withdrawETH(uint256 amount) external {
        assert(amount > 0);
        assert(accounts[msg.sender].balance >= amount);

        accounts[msg.sender].balance = accounts[msg.sender].balance.sub(amount);
        msg.sender.transfer(amount);
        Withdraw(msg.sender, amount);
    }

    function transferToAccount(uint256 pixelId, address toWallet, uint256 permil, uint256 gridPrice) internal {
        accounts[toWallet].balance = accounts[toWallet].balance.add(gridPrice.mul(permil).div(1000));
        Transfer(msg.sender, toWallet, gridPrice.mul(permil).div(1000), pixelId);
    }
}

contract EthColor is Ownable, EthColorAccount {
    using SafeMath for uint256;

    struct Pixel {
        uint256 color;
        uint256 times;
        address owner;
        uint256 price;
    }

    Pixel [16384] public pixels;

    string public constant name = "Ethcolor";
    string public constant version = "1.0.0";
    uint256 public constant initialPrice = 0.08 ether;

    event Drawcolor(uint256 indexed drawGridLocation, address indexed drawerAddress, uint256 colorDraw, uint256 spend);

    function getColors() constant public returns (uint256[16384]) {
        uint256[16384] memory result;
        for (uint256 i = 0; i < 16384; i++) {
            result[i] = pixels[i].color;
        }
        return result;
    }

    function getTimes() constant public returns (uint256[16384]) {
        uint256[16384] memory result;
        for (uint256 i = 0; i < 16384; i++) {
            result[i] = pixels[i].times;
        }
        return result;
    }

    function getOwners() constant public returns (address[16384]) {
        address[16384] memory result;
        for (uint256 i = 0; i < 16384; i++) {
            result[i] = pixels[i].owner;
        }
        return result;
    }

    function drawColors(uint256[] pixelIdxs, uint256[] colors, address referralAddress) payable public {
        assert(pixelIdxs.length == colors.length);

        // Set referral address
        if ((accounts[msg.sender].referrer == address(0)) &&
            (referralAddress != msg.sender) &&
            (referralAddress != address(0))) {

            accounts[msg.sender].referrer = referralAddress;
        }

        uint256 remainValue = msg.value;
        uint256 price;
        for (uint256 i = 0; i < pixelIdxs.length; i++) {
            uint256 pixelIdx = pixelIdxs[i];
            if (pixels[pixelIdx].times == 0) {
                price = initialPrice.mul(9).div(10);
            } else if (pixels[pixelIdx].times == 1){
                price = initialPrice.mul(11).div(10);
            } else {
                price = pixels[pixelIdx].price.mul(11).div(10);
            }

            if (remainValue < price) {
              // If the eth is not enough, the eth will be returned to his account on the contract.
              transferToAccount(pixelIdx, msg.sender, 1000, remainValue);
              break;
            }

            assert(colors[i] < 25);
            remainValue = remainValue.sub(price);

            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // Notify external contract about pixel update before state changes
            if (referralAddress != address(0) && referralAddress != msg.sender) {
                IPixelCallback(referralAddress).onPixelUpdate(pixelIdx, colors[i], price);
            }

            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            // Update pixel
            pixels[pixelIdx].color = colors[i];
            pixels[pixelIdx].times = pixels[pixelIdx].times.add(1);
            pixels[pixelIdx].price = price;
            Drawcolor(pixelIdx, msg.sender, colors[i], price);

            transferETH(pixelIdx , price);

            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // Update pixel owner AFTER external calls
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            pixels[pixelIdx].owner = msg.sender;
        }
    }

    // Transfer the ETH in contract balance
    function transferETH(uint256 pixelId, uint256 drawPrice) internal {
        // Transfer 97% to the last owner
        if (pixels[pixelId].times > 1) {
            transferToAccount(pixelId, pixels[pixelId].owner, 970, drawPrice);
        } else {
            transferToAccount(pixelId, wallet, 970, drawPrice);
        }

        if (accounts[msg.sender].referrer != address(0)) {
            // If account is referred, transfer 1% to referrer and 1% to referree
            transferToAccount(pixelId, accounts[msg.sender].referrer, 10, drawPrice);
            transferToAccount(pixelId, msg.sender, 10, drawPrice);
            transferToAccount(pixelId, wallet, 10, drawPrice);
        } else {
            transferToAccount(pixelId, wallet, 30, drawPrice);
        }
    }

    function finalize() onlyOwner public {
        require(msg.sender == wallet);
        // Check for after the end time: 2018/12/31 23:59:59 UTC
        require(now >= 1546300799);
        wallet.transfer(this.balance);
    }

    // Fallback function
    function () external {
    }
}
