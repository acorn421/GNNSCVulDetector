/*
 * ===== SmartInject Injection Details =====
 * Function      : withdrawETH
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added Pending Withdrawal State**: Introduced `pendingWithdrawals` mapping to track withdrawal attempts across transactions
 * 2. **Violated Checks-Effects-Interactions**: Moved the balance update after the external `transfer` call, creating a reentrancy window
 * 3. **Created Multi-Transaction Dependency**: The vulnerability requires multiple calls to accumulate pending withdrawals before exploitation
 * 
 * **Multi-Transaction Exploitation Process:**
 * - **Transaction 1**: User calls withdrawETH, pendingWithdrawals is incremented, but if reentrancy occurs, balance isn't updated yet
 * - **Transaction 2**: During reentrancy, attacker can call withdrawETH again with the same balance check passing since balance wasn't decremented
 * - **Transaction 3**: Continue exploiting until balance is finally updated, but pendingWithdrawals accumulates incorrectly
 * 
 * **Why Multi-Transaction Required:**
 * - The vulnerability depends on the persistent `pendingWithdrawals` state between transactions
 * - Single transaction exploitation would require the attacker to have control flow return to the same transaction, but the state corruption persists between separate transactions
 * - The exploit becomes more effective as pendingWithdrawals accumulates across multiple attempted withdrawals
 * 
 * This creates a realistic vulnerability where an attacker can exploit the time window between the external call and state update across multiple transactions, leveraging the persistent pendingWithdrawals state to drain more funds than they should be able to access.
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

contract Ownable {
    address public owner;
    address public wallet;

    function Ownable() internal {
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
    
    // Added missing declaration for pendingWithdrawals
    mapping(address => uint256) pendingWithdrawals;

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

        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Mark withdrawal as pending for this transaction
        pendingWithdrawals[msg.sender] = pendingWithdrawals[msg.sender].add(amount);
        
        // External call before state update - vulnerable to reentrancy
        msg.sender.transfer(amount);
        
        // Update balance after external call - creates reentrancy window
        accounts[msg.sender].balance = accounts[msg.sender].balance.sub(amount);
        
        // Clear pending withdrawal only after successful completion
        pendingWithdrawals[msg.sender] = pendingWithdrawals[msg.sender].sub(amount);
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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

            // Update pixel
            pixels[pixelIdx].color = colors[i];
            pixels[pixelIdx].times = pixels[pixelIdx].times.add(1);
            pixels[pixelIdx].price = price;
            Drawcolor(pixelIdx, msg.sender, colors[i], price);

            transferETH(pixelIdx , price);

            // Update pixel owner
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