/*
 * ===== SmartInject Injection Details =====
 * Function      : DistributeButtonIncome
 * Vulnerability : Reentrancy
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding a distributionIndex state variable that tracks distribution progress across multiple function calls. The vulnerability allows attackers to exploit the window between partial distributions where totalPot remains unchanged, enabling reentrancy attacks that drain funds over multiple transactions. The external calls occur before state cleanup, and the persistent distributionIndex creates a multi-transaction attack vector where malicious contracts can re-enter during the send() calls and manipulate the distribution process across several transactions.
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

    // <-- Added missing state variable -->
    uint256 private distributionIndex;
    
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
    constructor() public {
        owner = msg.sender;
   
        clickPrice = 0.01 ether;
        
        expireTime = block.timestamp + 360000;
        
        totalPot = 0;
        devFund = 0;
        clikerIndex = 0;
        totalPlayers = 0;
        // <-- Initialize distributionIndex -->
        distributionIndex = 0;
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
        
        uint256 reward = totalPot / CLICKERS_SIZE;
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Distribute rewards in batches to prevent gas limit issues
        uint256 batchSize = 5;
        uint256 startIndex = distributionIndex;
        uint256 endIndex = startIndex + batchSize;
        
        if(endIndex > CLICKERS_SIZE) {
            endIndex = CLICKERS_SIZE;
        }
        
        for(uint256 i = startIndex; i < endIndex; ++i)
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        {
            if(!clickers[i].send(reward))
            {
                // oops
            }
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        distributionIndex = endIndex;
        
        // Only reset totalPot when all distributions are complete
        if(distributionIndex >= CLICKERS_SIZE) {
            totalPot = 0;
            distributionIndex = 0;
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
