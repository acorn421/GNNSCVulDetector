/*
 * ===== SmartInject Injection Details =====
 * Function      : DistributeButtonIncome
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
 * Introduced a progressive reward decay mechanism based on block.timestamp that creates a stateful, multi-transaction timestamp dependence vulnerability. The function now calculates rewards based on time elapsed since expiry (timeSinceExpiry = block.timestamp - expireTime), with rewards decreasing by 1% every 60 seconds. 
 * 
 * Key vulnerability aspects:
 * 1. **Timestamp Manipulation**: Miners can manipulate block.timestamp to control the decay calculation, affecting reward amounts
 * 2. **Multi-Transaction State**: The function no longer resets totalPot to 0 immediately, allowing multiple distribution calls with different timestamp manipulations
 * 3. **Progressive Exploitation**: Attackers need multiple transactions to fully exploit - first to trigger initial distribution, then manipulate timestamps across subsequent blocks to optimize reward extraction
 * 4. **State Persistence**: The totalPot state persists between calls, enabling accumulated exploitation across multiple transactions
 * 
 * The vulnerability requires at least 2 transactions to exploit effectively: one to establish the initial distribution state, and subsequent transactions with manipulated timestamps to extract optimal rewards from the remaining totalPot balance.
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
        
        expireTime = block.timestamp + EXPIRE_DELAY;
        
        address refAddr = referee;
        
        // a player who never played cannot be referenced
        if(refAddr == 0 || playerClickCount[referee] == 0)
            refAddr = owner;
            
        if(totalClicks > CLICKERS_SIZE)
        {
            totalPot = totalPot.add(((msg.value.mul(8)) / 10));
            
            uint256 fee = msg.value / 10;
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
            clickPrice += 0.01 ether;
            clikerIndex = 0;
        }
    }
    
    function DistributeButtonIncome() external
    {
        require(expireTime < block.timestamp);
        require(totalPot > 0);
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Track distribution timing for progressive reward decay
        uint256 timeSinceExpiry = block.timestamp - expireTime;
        
        // Base reward calculation
        uint256 baseReward = totalPot / CLICKERS_SIZE;
        
        // Progressive decay: rewards decrease by 1% every 60 seconds after expiry
        // This creates incentive for quick distribution but allows timestamp manipulation
        uint256 decayPeriods = timeSinceExpiry / 60;
        uint256 decayPercentage = decayPeriods > 50 ? 50 : decayPeriods; // Cap at 50%
        
        uint256 reward = baseReward - (baseReward * decayPercentage / 100);
        
        // Store the undistributed amount back to totalPot for future distributions
        // This enables multi-transaction exploitation
        uint256 totalDistributed = 0;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        
        for(uint256 i = 0; i < CLICKERS_SIZE; ++i)
        {
            if(!clickers[i].send(reward))
            {
                // oops
            }
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
            totalDistributed += reward;
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        }
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Update totalPot with remaining undistributed funds
        // This maintains state between multiple distribution calls
        totalPot = totalPot > totalDistributed ? totalPot - totalDistributed : 0;
        
        // Only reset totalPot to 0 if all funds have been distributed
        if(totalPot < (baseReward / 100)) // Less than 1% of original reward left
        {
            totalPot = 0;
        }
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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