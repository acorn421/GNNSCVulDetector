/*
 * ===== SmartInject Injection Details =====
 * Function      : drawColors
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a time-based discount system that relies on block.timestamp to determine pricing across multiple transactions. The vulnerability allows miners to manipulate timestamps to exploit favorable pricing conditions that require state accumulation from previous transactions. A new field 'lastPurchaseTime' must be added to the Pixel struct to store the timestamp of the last purchase, creating a stateful vulnerability that requires multiple transactions to exploit effectively.
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

    constructor() public {
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
    function getAccountBalance(address userAddress) public view returns (uint256) {
        return accounts[userAddress].balance;
    }
    function getAccountReferrer(address userAddress) public view returns (address) {
        return accounts[userAddress].referrer;
    }

    // To withdraw your account balance from this contract.
    function withdrawETH(uint256 amount) external {
        assert(amount > 0);
        assert(accounts[msg.sender].balance >= amount);

        accounts[msg.sender].balance = accounts[msg.sender].balance.sub(amount);
        msg.sender.transfer(amount);
        emit Withdraw(msg.sender, amount);
    }

    function transferToAccount(uint256 pixelId, address toWallet, uint256 permil, uint256 gridPrice) internal {
        accounts[toWallet].balance = accounts[toWallet].balance.add(gridPrice.mul(permil).div(1000));
        emit Transfer(msg.sender, toWallet, gridPrice.mul(permil).div(1000), pixelId);
    }
}

contract EthColor is Ownable, EthColorAccount {
    using SafeMath for uint256;

    struct Pixel {
        uint256 color;
        uint256 times;
        address owner;
        uint256 price;
        uint256 lastPurchaseTime; // <-- ADDED MISSING FIELD
    }

    Pixel [16384] public pixels;

    string public constant name = "Ethcolor";
    string public constant version = "1.0.0";
    uint256 public constant initialPrice = 0.08 ether;

    event Drawcolor(uint256 indexed drawGridLocation, address indexed drawerAddress, uint256 colorDraw, uint256 spend);

    function getColors() public view returns (uint256[16384]) {
        uint256[16384] memory result;
        for (uint256 i = 0; i < 16384; i++) {
            result[i] = pixels[i].color;
        }
        return result;
    }

    function getTimes() public view returns (uint256[16384]) {
        uint256[16384] memory result;
        for (uint256 i = 0; i < 16384; i++) {
            result[i] = pixels[i].times;
        }
        return result;
    }

    function getOwners() public view returns (address[16384]) {
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
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
            
            // Time-based pricing with vulnerability: using block.timestamp for pricing calculation
            uint256 basePrice;
            if (pixels[pixelIdx].times == 0) {
                basePrice = initialPrice.mul(9).div(10);
            } else if (pixels[pixelIdx].times == 1){
                basePrice = initialPrice.mul(11).div(10);
            } else {
                basePrice = pixels[pixelIdx].price.mul(11).div(10);
            }
            
            // VULNERABILITY: Time-based discount system that depends on block.timestamp
            // If pixel was last purchased more than 1 hour ago, apply 20% discount
            // This creates a multi-transaction vulnerability where miners can manipulate timestamps
            if (pixels[pixelIdx].times > 0 && (block.timestamp - pixels[pixelIdx].lastPurchaseTime) > 3600) {
                price = basePrice.mul(80).div(100); // 20% discount
            } else {
                price = basePrice;
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
            pixels[pixelIdx].lastPurchaseTime = block.timestamp; // Store timestamp for future discount calculations
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
            emit Drawcolor(pixelIdx, msg.sender, colors[i], price);

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
    function () public {
    }
}
