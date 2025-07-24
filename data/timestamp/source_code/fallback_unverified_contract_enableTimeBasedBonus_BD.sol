/*
 * ===== SmartInject Injection Details =====
 * Function      : enableTimeBasedBonus
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 12 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a timestamp dependence issue in a multi-transaction bonus system. The vulnerability requires multiple transactions to exploit: 1) Owner enables bonus system, 2) User makes purchase to become eligible, 3) User claims bonus tokens. The calculateBonusAmount function is vulnerable to timestamp manipulation by miners who can adjust block timestamps to increase the bonus multiplier, allowing them to claim significantly more tokens than intended. The vulnerability is stateful as it depends on bonusStartTime, welfare mapping, and lastBonusClaimTime mapping that persist across transactions.
 */
pragma solidity ^0.4.25;

/**
 * VNET Token Pre-Sale Contract
 * 
 * Send ETH here, and you will receive the VNET Tokens immediately.
 * 
 * https://vision.network/
 */

/**
 * @title ERC20Basic
 * @dev Simpler version of ERC20 interface
 * @dev see https://github.com/ethereum/EIPs/issues/179
 */
contract ERC20Basic {
    function totalSupply() public view returns (uint256);
    function balanceOf(address _who) public view returns (uint256);
    function transfer(address _to, uint256 _value) public returns (bool);
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
}

/**
 * @title Ownable
 * @dev The Ownable contract has an owner address, and provides basic authorization control
 * functions, this simplifies the implementation of "user permissions".
 */
contract Ownable {
    address public owner;

    event OwnershipTransferred(address indexed _previousOwner, address indexed _newOwner);

    /**
     * @dev The Ownable constructor sets the original `owner` of the contract to the sender
     * account.
     */
    constructor() public {
        owner = msg.sender;
    }

    /**
     * @dev Throws if called by any account other than the owner.
     */
    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    /**
     * @dev Allows the current owner to transfer control of the contract to a newOwner.
     * @param _newOwner The address to transfer ownership to.
     */
    function transferOwnership(address _newOwner) public onlyOwner {
        require(_newOwner != address(0));
        emit OwnershipTransferred(owner, _newOwner);
        owner = _newOwner;
    }

    /**
     * @dev Rescue compatible ERC20Basic Token
     *
     * @param _token ERC20Basic The address of the token contract
     */
    function rescueTokens(ERC20Basic _token, address _receiver) external onlyOwner {
        uint256 balance = _token.balanceOf(this);
        assert(_token.transfer(_receiver, balance));
    }
}

/**
 * @title SafeMath
 * @dev Math operations with safety checks that throw on error
 */
library SafeMath {
    /**
     * @dev Multiplies two numbers, throws on overflow.
     */
    function mul(uint256 a, uint256 b) internal pure returns (uint256 c) {
        if (a == 0) {
            return 0;
        }
        c = a * b;
        assert(c / a == b);
        return c;
    }

    /**
     * @dev Integer division of two numbers, truncating the quotient.
     */
    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        // assert(b > 0); // Solidity automatically throws when dividing by 0
        // uint256 c = a / b;
        // assert(a == b * c + a % b); // There is no case in which this doesn't hold
        return a / b;
    }

    /**
     * @dev Adds two numbers, throws on overflow.
     */
    function add(uint256 a, uint256 b) internal pure returns (uint256 c) {
        c = a + b;
        assert(c >= a);
        return c;
    }

    /**
     * @dev Subtracts two numbers, throws on overflow (i.e. if subtrahend is greater than minuend).
     */
    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        assert(b <= a);
        return a - b;
    }
}

/**
 * @title VNET Token Pre-Sale
 */
contract VNETTokenPreSale is Ownable {
    using SafeMath for uint256;

    string public description = "VNET Token Pre-Sale Contract";
    
    ERC20Basic public vnetToken;
    address wallet;
    uint256 public ratioNext; // with 6 decimals
    uint256 public ethPrice; // with 8 decimals
    uint256 public vnetSold; // with 8 decimals
    uint256 public vnetSupply = 30 * (10 ** 8) * (10 ** 6); // 30 billion supply
    uint256 public vnetPriceStart = 260000; // 0.0026 * (10 ** 8)
    uint256 public vnetPriceTarget = 650000; // 0.0065 * (10 ** 8)
    uint256 public weiMinimum = 1 * (10 ** 18); // 1 Ether
    uint256 public weiMaximum = 100 * (10 ** 18); // 100 Ether
    uint256 public weiWelfare = 10 * (10 ** 18); // 10 Ether

    mapping(address => bool) public welfare;

    // === START FALLBACK INJECTION STATE VARS ===
    uint256 public bonusStartTime;
    uint256 public bonusEndTime;
    uint256 public bonusPercentage; // with 2 decimals (e.g., 1500 = 15.00%)
    bool public bonusEnabled = false;
    mapping(address => uint256) public lastBonusClaimTime;
    // === END FALLBACK INJECTION STATE VARS ===

    event Welfare(address indexed _buyer);
    event BuyVNET(address indexed _buyer, uint256 _ratio, uint256 _vnetAmount, uint256 _weiAmount);
    event EthPrice(uint256 _ethPrice);
    event BonusEnabled(uint256 _startTime, uint256 _endTime, uint256 _percentage);
    event BonusTokensClaimed(address indexed _claimer, uint256 _amount);

    /**
     * @dev Constructor
     */
    constructor(ERC20Basic _vnetToken, uint256 _ethPrice) public {
        vnetToken = _vnetToken;
        wallet = owner;
        calcRatioNext();
        updateEthPrice(_ethPrice);
    }

    /**
     * @dev Enable time-based bonus system
     */
    function enableTimeBasedBonus(uint256 _durationHours, uint256 _bonusPercentage) onlyOwner public {
        require(!bonusEnabled, "Bonus already enabled");
        require(_durationHours > 0, "Duration must be positive");
        require(_bonusPercentage > 0 && _bonusPercentage <= 5000, "Invalid bonus percentage");
        
        bonusStartTime = now;
        bonusEndTime = now + (_durationHours * 1 hours);
        bonusPercentage = _bonusPercentage;
        bonusEnabled = true;
        
        emit BonusEnabled(bonusStartTime, bonusEndTime, bonusPercentage);
    }

    /**
     * @dev Check if bonus is currently active
     */
    function isBonusActive() public view returns (bool) {
        return bonusEnabled && now >= bonusStartTime && now <= bonusEndTime;
    }

    /**
     * @dev Claim bonus tokens based on previous purchases
     */
    function claimBonusTokens() public {
        require(isBonusActive(), "Bonus not active");
        require(welfare[msg.sender], "Not eligible for bonus");
        require(lastBonusClaimTime[msg.sender] == 0 || now >= lastBonusClaimTime[msg.sender] + 1 hours, "Bonus already claimed recently");
        
        uint256 vnetBalance = vnetToken.balanceOf(address(this));
        require(vnetBalance > 0, "No tokens available");
        
        // Calculate bonus amount based on time manipulation vulnerability
        uint256 bonusAmount = calculateBonusAmount(msg.sender);
        require(bonusAmount > 0, "No bonus available");
        
        if (vnetBalance >= bonusAmount) {
            lastBonusClaimTime[msg.sender] = now;
            assert(vnetToken.transfer(msg.sender, bonusAmount));
            emit BonusTokensClaimed(msg.sender, bonusAmount);
        }
    }

    /**
     * @dev Calculate bonus amount (vulnerable to timestamp manipulation)
     */
    function calculateBonusAmount(address _user) private view returns (uint256) {
        if (!welfare[_user]) return 0;
        
        // Vulnerable calculation based on timestamp
        uint256 timeElapsed = now - bonusStartTime;
        uint256 multiplier = (timeElapsed / 1 hours) + 1;
        
        // Base bonus calculation with timestamp dependency
        uint256 baseBonus = (vnetSold * bonusPercentage) / 10000;
        uint256 bonusAmount = (baseBonus * multiplier) / 100;
        
        return bonusAmount;
    }

    /**
     * @dev receive ETH and send tokens
     */
    function () public payable {
        // Make sure token balance > 0
        uint256 vnetBalance = vnetToken.balanceOf(address(this));
        require(vnetBalance > 0);
        require(vnetSold < vnetSupply);
        
        // Minimum & Maximum Limit
        uint256 weiAmount = msg.value;
        require(weiAmount >= weiMinimum);
        require(weiAmount <= weiMaximum);

        // VNET Token Amount to be transfer
        uint256 vnetAmount = weiAmount.mul(ratioNext).div(10 ** 18);

        // Transfer VNET
        if (vnetBalance >= vnetAmount) {
            assert(vnetToken.transfer(msg.sender, vnetAmount));
            emit BuyVNET(msg.sender, ratioNext, vnetAmount, weiAmount);
            vnetSold = vnetSold.add(vnetAmount);
            if (weiAmount >= weiWelfare) {
                welfare[msg.sender] = true;
                emit Welfare(msg.sender);
            }
        } else {
            uint256 weiExpend = vnetBalance.mul(10 ** 18).div(ratioNext);
            assert(vnetToken.transfer(msg.sender, vnetBalance));
            emit BuyVNET(msg.sender, ratioNext, vnetBalance, weiExpend);
            vnetSold = vnetSold.add(vnetBalance);
            msg.sender.transfer(weiAmount.sub(weiExpend));
            if (weiExpend >= weiWelfare) {
                welfare[msg.sender] = true;
                emit Welfare(msg.sender);
            }
        }

        // Calculate: ratioNext
        calcRatioNext();

        // transfer Ether
        uint256 etherBalance = address(this).balance;
        wallet.transfer(etherBalance);
    }

    /**
     * @dev calculate ration next
     */
    function calcRatioNext() private {
        ratioNext = ethPrice.mul(10 ** 6).div(vnetPriceStart.add(vnetPriceTarget.sub(vnetPriceStart).mul(vnetSold).div(vnetSupply)));
    }

    /**
     * @dev update wallet
     */
    function updateWallet(address _wallet) onlyOwner public {
        wallet = _wallet;
    }

    /**
     * @dev update ETH Price
     */
    function updateEthPrice(uint256 _ethPrice) onlyOwner public {
        ethPrice = _ethPrice;
        emit EthPrice(_ethPrice);
        calcRatioNext();
    }
}
