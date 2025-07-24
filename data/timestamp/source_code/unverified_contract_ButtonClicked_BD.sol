/*
 * ===== SmartInject Injection Details =====
 * Function      : ButtonClicked
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
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability through three key modifications:
 * 
 * 1. **Streak Bonus Calculation**: Added vulnerable logic that calculates bonus payouts based on the time difference between consecutive clicks. The calculation uses `block.timestamp - expireTime + EXPIRE_DELAY` to determine timing, which can be manipulated by miners across multiple transactions to artificially inflate bonuses.
 * 
 * 2. **Timestamp-Based Fee Reduction**: Modified the fee calculation to depend on whether `block.timestamp % 2 == 0`, giving reduced fees for even timestamp blocks. This creates a predictable pattern that miners can exploit by manipulating timestamps across multiple transactions.
 * 
 * 3. **Timestamp-Dependent Price Increases**: Changed the click price increase logic to vary based on `block.timestamp % 10 < 3`, allowing for reduced price increases during certain timestamp ranges.
 * 
 * **Multi-Transaction Exploitation Path**:
 * - Transaction 1: Attacker clicks button during favorable timestamp conditions (even timestamp for reduced fees)
 * - Transaction 2: Miner manipulates timestamp to create optimal time difference for streak bonus
 * - Transaction 3: Exploit reduced price increase window by timing clicks when `block.timestamp % 10 < 3`
 * - Transactions 4+: Repeat pattern to accumulate unfair advantages through timestamp manipulation
 * 
 * This vulnerability requires multiple transactions because:
 * - The streak bonus depends on state changes between clicks (previous expireTime vs current block.timestamp)
 * - The exploitation requires building up accumulated advantages over multiple clicks
 * - Miners need multiple blocks to effectively manipulate timestamps for maximum benefit
 * - The price increase manipulation affects future transaction costs, requiring strategic timing across multiple calls
 */
pragma solidity ^0.4.18;

library SafeMath {
    function add(uint256 a, uint256 b) internal pure returns (uint256 c) {
        c = a + b;
        require(c >= a);
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256 c) {
        require(b <= a);
        c = a - b;
    }

    function mul(uint256 a, uint256 b) internal pure returns (uint256 c) {
        c = a * b;
        require(a == 0 || c / a == b);
    }
}

//-----------------------------------------------------------------------
contract ETHButton {
    using SafeMath for uint256;
    
    address private owner;
    
    // game data
    uint256 private constant CLICKERS_SIZE = 30;
    uint256 private constant EXPIRE_DELAY = 3600;
    address[CLICKERS_SIZE] private clickers;
    uint256 private clickPrice;
    uint256 private clikerIndex;
    uint256 private expireTime;
    uint256 private totalPot;
    uint256 private devFund;
    
    // statistics
    mapping(address=>uint256) private playerClickCount;
    mapping(address=>uint256) private playerSecToTimeout;
    uint256 private totalClicks;
    
    // index to address mapping
    mapping(uint256=>address) private playerIndexes;
    uint256 private totalPlayers;
    
    // referal system
    mapping(address=>uint256) private playerReferedByCount;
    mapping(address=>uint256) private playerReferedMoneyGain;
    
    // ------------------------------------------------------------------------
    // Constructor
    // ------------------------------------------------------------------------
    function ETHButton() public {
        owner = msg.sender;
   
        clickPrice = 0.01 ether;
        
        expireTime = block.timestamp + 360000;
        
        totalPot = 0;
        devFund = 0;
        clikerIndex = 0;
        totalPlayers = 0;
    }
    
    //--------------------------------------------------------------------------
    // GET functions 
    //--------------------------------------------------------------------------
    function GetTotalPlayers() external view returns(uint256)
    {
        return totalPlayers;
    }
    
    function GetTotalClicks() external view returns(uint256)
    {
        return totalClicks;
    }
    
    function GetTotalPot() external view returns(uint256)
    {
        return totalPot;
    }
    
    function GetExpireTime() external view returns(uint256)
    {
        return expireTime;
    }
    
    function GetClickPrice() external view returns(uint256)
    {
        return clickPrice;
    }
    
    function GetPlayerAt(uint256 idx) external view returns (address)
    {
        require(idx < totalPlayers);
        
        return playerIndexes[idx];
    }
    
    function GetPlayerDataAt(address player) external view returns(uint256 _playerClickCount, uint256 _playerSecToTimeout, 
    uint256 _referCount, uint256 _referalRevenue)
    {
        _playerClickCount = playerClickCount[player];
        _playerSecToTimeout = playerSecToTimeout[player];
        _referCount = playerReferedByCount[player];
        _referalRevenue = playerReferedMoneyGain[player];
    }
    
    function GetWinnerAt(uint256 idx) external view returns (address _addr)
    {
        require(idx < CLICKERS_SIZE);
        
        if(idx < clikerIndex)
            _addr = clickers[clikerIndex-(idx+1)];
        else
            _addr = clickers[(clikerIndex + CLICKERS_SIZE) - (idx+1)];
    }
    
    function GetWinners() external view returns (address[CLICKERS_SIZE] _addr)
    {
        for(uint256 idx = 0; idx < CLICKERS_SIZE; ++idx)
        {
            if(idx < clikerIndex)
                _addr[idx] = clickers[clikerIndex-(idx+1)];
            else
                _addr[idx] = clickers[(clikerIndex + CLICKERS_SIZE) - (idx+1)];
        }
    }
    
    //--------------------------------------------------------------------------
    // Game Mechanics
    //--------------------------------------------------------------------------
    function ButtonClicked(address referee) external payable
    {
        require(msg.value >= clickPrice);
        require(expireTime >= block.timestamp);
        require(referee != msg.sender);
        
        if(playerClickCount[msg.sender] == 0)
        {
            playerIndexes[totalPlayers] = msg.sender;
            totalPlayers += 1;
        }
        
        totalClicks += 1;
        playerClickCount[msg.sender] += 1;
        if(playerSecToTimeout[msg.sender] == 0 || playerSecToTimeout[msg.sender] > (expireTime - block.timestamp))
            playerSecToTimeout[msg.sender] = expireTime - block.timestamp;
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Vulnerable timestamp manipulation: Store historical timestamp for "streak" bonus calculation
        uint256 timeSinceLastClick = block.timestamp - expireTime + EXPIRE_DELAY;
        if(timeSinceLastClick > 0 && timeSinceLastClick <= 60) {
            // Bonus for quick consecutive clicks - vulnerable to timestamp manipulation
            totalPot = totalPot.add(msg.value.mul(timeSinceLastClick) / 100);
        }
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        expireTime = block.timestamp + EXPIRE_DELAY;
        
        address refAddr = referee;
        
        // a player who never played cannot be referenced
        if(refAddr == 0 || playerClickCount[referee] == 0)
            refAddr = owner;
            
        if(totalClicks > CLICKERS_SIZE)
        {
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
            // Vulnerable: Use stored timestamp for fee calculation
            uint256 baseValue = msg.value;
            if(block.timestamp % 2 == 0) {
                // Even timestamp blocks get reduced fees (manipulable by miners)
                baseValue = msg.value.mul(85) / 100;
            }
            
            totalPot = totalPot.add(((baseValue.mul(8)) / 10));
            
            uint256 fee = baseValue / 10;
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
            devFund += fee;
            
            // don't try to hack the system with invalid addresses...
            if(!refAddr.send(fee))
            {
                // if I write "totalPot" here everybody will exploit 
                // the referal system with invalid address
                devFund += fee;
            } else
            {
                playerReferedByCount[refAddr] += 1;
                playerReferedMoneyGain[refAddr] += fee;
            }
        } else
        {
            // until CLICKERS_SIZE total clicks don't take dev funds, so the first clikcers
            // don't risk 20% negative interest
            totalPot += msg.value;
        }
        
        clickers[clikerIndex] = msg.sender;
        clikerIndex += 1;
       
        if(clikerIndex >= CLICKERS_SIZE)
        {
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
            // Vulnerable: Price increase based on timestamp manipulation
            uint256 priceIncrease = 0.01 ether;
            if(block.timestamp % 10 < 3) {
                // Lower price increase for certain timestamp ranges
                priceIncrease = 0.005 ether;
            }
            clickPrice += priceIncrease;
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
            clikerIndex = 0;
        }
    }
    
    function DistributeButtonIncome() external
    {
        require(expireTime < block.timestamp);
        require(totalPot > 0);
        
        uint256 reward = totalPot / CLICKERS_SIZE;
        
        for(uint256 i = 0; i < CLICKERS_SIZE; ++i)
        {
            if(!clickers[i].send(reward))
            {
                // oops
            }
        }
        
        totalPot = 0;
    }
    //--------------------------------------------------------------------------
    // Funds menagement
    //--------------------------------------------------------------------------
    function WithdrawDevFunds() external
    {
        require(msg.sender == owner);

        if(owner.send(devFund))
        {
            devFund = 0;
        }
    }
}