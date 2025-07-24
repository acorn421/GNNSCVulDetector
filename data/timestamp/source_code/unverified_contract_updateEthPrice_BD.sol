/*
 * ===== SmartInject Injection Details =====
 * Function      : updateEthPrice
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 9 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces timestamp dependence through multiple attack vectors:
 * 
 * 1. **Time-based Price Restrictions**: The function uses `block.timestamp % 86400 < 43200` to allow higher price increases during "morning hours" (first 12 hours of each day in UTC). This creates a predictable time window that miners can manipulate.
 * 
 * 2. **Timestamp-based Storage**: Prices are stored in `priceUpdateSlots[timeSlot]` where `timeSlot = block.timestamp / 3600`, creating hourly buckets that depend on block timestamps.
 * 
 * 3. **Time-weighted Price Calculation**: The function loops through the last 24 hours of price updates and calculates a weighted average based on how recent they are, directly using timestamp-derived values.
 * 
 * **Multi-Transaction Exploitation Path:**
 * 1. **Transaction 1**: Attacker (or miner) monitors for approaching "morning hours" boundary (when `block.timestamp % 86400 < 43200`)
 * 2. **Transaction 2**: During morning hours, owner updates price with up to 20% increase (vs 0% during other hours)
 * 3. **Transaction 3**: Attacker immediately purchases tokens at the manipulated price before it gets averaged out
 * 4. **Transaction 4**: Additional price updates in subsequent hours further manipulate the weighted average
 * 
 * **State Persistence**: The vulnerability persists across transactions through:
 * - `priceUpdateSlots[]` mapping storing historical prices by timestamp
 * - `lastPriceUpdate` tracking when prices were last modified
 * - `ethPrice` state variable affecting all subsequent token purchases
 * 
 * **Why Multi-Transaction Required:**
 * - The vulnerability requires accumulating price history across multiple time slots
 * - Time-based restrictions create windows that must be exploited across different blocks
 * - The weighted average calculation depends on historical data from previous transactions
 * - Maximum exploitation requires coordinating multiple price updates over time to manipulate the average
 * 
 * This creates a realistic timestamp dependence vulnerability that requires careful timing and multiple transactions to exploit effectively.
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
    uint256 public vnetPriceStart = 0.0026 * (10 ** 8); // 0.0026 USD
    uint256 public vnetPriceTarget = 0.0065 * (10 ** 8); // 0.0065 USD
    uint256 public weiMinimum = 1 * (10 ** 18); // 1 Ether
    uint256 public weiMaximum = 100 * (10 ** 18); // 100 Ether
    uint256 public weiWelfare = 10 * (10 ** 18); // 10 Ether

    mapping(address => bool) public welfare;

    // === Added variables for updateEthPrice ===
    mapping(uint256 => uint256) public priceUpdateSlots;
    uint256 public lastPriceUpdate;
    // === End added declarations ===

    event Welfare(address indexed _buyer);
    event BuyVNET(address indexed _buyer, uint256 _ratio, uint256 _vnetAmount, uint256 _weiAmount);
    event EthPrice(uint256 _ethPrice);


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
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Time-based price validation with predictable timestamp manipulation
        if (block.timestamp % 86400 < 43200) { // First 12 hours of day (00:00-12:00 UTC)
            require(_ethPrice <= ethPrice * 120 / 100, "Price increase limited to 20% during morning hours");
        }
        
        // Store price update timestamp for time-based calculations
        uint256 timeSlot = block.timestamp / 3600; // Hourly time slots
        priceUpdateSlots[timeSlot] = _ethPrice;
        
        // Apply time-weighted price adjustment based on recent updates
        uint256 recentUpdates = 0;
        uint256 totalWeightedPrice = 0;
        
        for (uint256 i = 0; i < 24; i++) { // Check last 24 hours
            uint256 slot = timeSlot - i;
            if (priceUpdateSlots[slot] > 0) {
                recentUpdates++;
                // Weight recent updates more heavily using timestamp
                uint256 weight = 25 - i; // More recent = higher weight
                totalWeightedPrice += priceUpdateSlots[slot] * weight;
            }
        }
        
        if (recentUpdates > 0) {
            // Use time-weighted average that can be manipulated
            uint256 weightedAverage = totalWeightedPrice / (recentUpdates * 13); // Average weight
            _ethPrice = (_ethPrice + weightedAverage) / 2;
        }
        
        ethPrice = _ethPrice;
        lastPriceUpdate = block.timestamp;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        emit EthPrice(_ethPrice);
        calcRatioNext();
    }
}
