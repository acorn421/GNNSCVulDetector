/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleTimedMigration
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 7 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces timestamp dependence that requires multiple transactions to exploit. The vulnerability manifests through a two-step process: first scheduling a migration with a future timestamp, then executing it when the timestamp is reached. Miners can manipulate block.timestamp between these transactions to either delay or accelerate the migration execution, potentially allowing unauthorized early access to migration functions or preventing legitimate execution.
 */
pragma solidity ^0.4.8;

contract ICreditBIT{
    function mintMigrationTokens(address _reciever, uint _amount) returns (uint error) {}
}

contract CreditMC {

    struct MigrationAccount{
        string legacyCreditAddresses;
        address newCreditAddress;
        uint creditbitsDeposited;
        uint newTotalSupplyVote;
        uint coreDevteamRewardVote;
    }
    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    uint public migrationScheduleTime;
    bool public migrationScheduled;
    
    function scheduleTimedMigration(uint _migrationTime) returns (uint error) {
        if (msg.sender != dev) { return 1; }
        if (migrationEnded) { return 1; }
        if (migrationScheduled) { return 1; }
        
        // Vulnerability: Uses block.timestamp which can be manipulated by miners
        if (_migrationTime <= block.timestamp) { return 1; }
        
        migrationScheduleTime = _migrationTime;
        migrationScheduled = true;
        return 0;
    }
    
    function executeMigrationSchedule() returns (uint error) {
        if (msg.sender != dev) { return 1; }
        if (!migrationScheduled) { return 1; }
        if (migrationEnded) { return 1; }
        
        // Vulnerability: Timestamp dependence - miners can manipulate block.timestamp
        // This creates a multi-transaction vulnerability where:
        // 1. First transaction: scheduleTimedMigration() sets the time
        // 2. Second transaction: executeMigrationSchedule() checks the time
        // Between these transactions, miners can manipulate timestamps
        if (block.timestamp < migrationScheduleTime) { return 1; }
        
        migrationEnded = true;
        migrationScheduled = false;
        return 0;
    }
    // === END FALLBACK INJECTION ===

    address public dev;
    address public curator;
    bool public migrationEnded;
    bool public devRewardClaimed;
    bool public daoStakeClaimed;

    ICreditBIT creditbitContract;

    uint public creditsExchanged;
    uint public realVotedSupply;
    uint public realSupplyWeight;
    uint public realDevReward;
    uint public realDevRewardWeight;
    
    function getCurrentSupplyVote() constant returns(uint supplyVote){
        return realVotedSupply / 10**8;
    }
    function getCurrentDevReward() constant returns(uint rewardVote){
        return ((((realVotedSupply - creditsExchanged) * (realDevReward))) / 10000) / 10**8;
    }
    function getCurrentDaoStakeSupply() constant returns(uint rewardVote){
        return ((((realVotedSupply - creditsExchanged) * (10000 - realDevReward))) / 10000) / 10**8;
    }
    function getCurrentCreditsExchanged() constant returns(uint crbExchanged){
        return creditsExchanged / 10**8;
    }
    
    function getMigrationAccount(address _accountAddress) constant returns (bytes, address, uint, uint, uint){
        MigrationAccount memory tempMigrationAccount = MigrationAccounts[AccountLocation[_accountAddress]];
        return (bytes(tempMigrationAccount.legacyCreditAddresses), 
            tempMigrationAccount.newCreditAddress, 
            tempMigrationAccount.creditbitsDeposited,
            tempMigrationAccount.newTotalSupplyVote,
            tempMigrationAccount.coreDevteamRewardVote
        );
    }

    uint public migrationAccountCounter;
    mapping (uint => MigrationAccount) MigrationAccounts;
    mapping (address => uint) AccountLocation;

    function CreditMC(){
        dev = msg.sender;
        migrationAccountCounter = 1;
        migrationEnded = false;
        devRewardClaimed = false;
    }

    function addNewAccount(string _legacyCreditAddress, address _etherAddress, uint _numberOfCoins, uint _totalSupplyVote, uint _coreDevTeamReward) returns (uint error){
        if (migrationEnded) {return 1;}
        if (msg.sender != curator){ return 1; }

        uint location;
        uint message;
        
        if (AccountLocation[_etherAddress] == 0){
            migrationAccountCounter += 1;
            location = migrationAccountCounter;
            
            message = creditbitContract.mintMigrationTokens(_etherAddress, _numberOfCoins);
            if (message == 0 && address(creditbitContract) != 0x0){
                MigrationAccounts[location].legacyCreditAddresses = _legacyCreditAddress;
                MigrationAccounts[location].newCreditAddress = _etherAddress;
                MigrationAccounts[location].creditbitsDeposited = _numberOfCoins;
                MigrationAccounts[location].newTotalSupplyVote = _totalSupplyVote;
                MigrationAccounts[location].coreDevteamRewardVote = _coreDevTeamReward;
                AccountLocation[_etherAddress] = location;
                
                creditsExchanged += _numberOfCoins;
                calculateVote(_totalSupplyVote, _coreDevTeamReward, _numberOfCoins);
            }else{
                return 1;
            }
        }else{
            location = AccountLocation[_etherAddress];
            message = creditbitContract.mintMigrationTokens(_etherAddress, _numberOfCoins);
            if (message == 0 && address(creditbitContract) != 0x0){
                MigrationAccounts[location].creditbitsDeposited += _numberOfCoins;
                
                creditsExchanged += _numberOfCoins;
                calculateVote(_totalSupplyVote, _coreDevTeamReward, _numberOfCoins);
            }else{
                return 1;
            }
        }
        return 0;
    }
    //todo: check on testnet
    function calculateVote(uint _newSupplyVote, uint _newRewardVote, uint _numOfVotes) internal{
        uint newSupply = (realVotedSupply * realSupplyWeight + _newSupplyVote * _numOfVotes) / (realSupplyWeight + _numOfVotes);
        uint newDevReward = (1000000*realDevReward * realDevRewardWeight + 1000000 * _newRewardVote * _numOfVotes) / (realDevRewardWeight + _numOfVotes);
    
        realVotedSupply = newSupply;
        realSupplyWeight = realSupplyWeight + _numOfVotes;
        realDevReward = newDevReward/1000000;
        realDevRewardWeight = realDevRewardWeight + _numOfVotes;
    }

    function setCreditMCCurator(address _curatorAddress) returns (uint error){
        if (msg.sender != dev){ return 1; }

        curator = _curatorAddress;
        return 0;
    }
    
    function setCreditbit(address _bitAddress) returns (uint error){
        if (msg.sender != dev) {return 1;}
        
        creditbitContract = ICreditBIT(_bitAddress);
        return 0;
    }
    function getCreditbitAddress() constant returns (address bitAddress){
        return address(creditbitContract);
    }
    
    function endMigration() returns (uint error){
        if (msg.sender != dev){ return 1; }
        
        migrationEnded = true;
        return 0;
    }
    
    
    function claimDevReward(address _recipient) returns (uint error){
        if (msg.sender != dev){ return 1; }
        if (devRewardClaimed){ return 1; }
        if (!migrationEnded){ return 1;}
        
        uint message = creditbitContract.mintMigrationTokens(
            _recipient, 
            (((realVotedSupply - creditsExchanged) * (realDevReward)) / 10000)
        );
        if (message != 0) { return 1; }
        
        creditsExchanged += (((realVotedSupply - creditsExchanged) * (realDevReward)) / 10000);
        devRewardClaimed = true;
        return 0;
    }
    
    function claimDaoStakeSupply(address _recipient) returns (uint error){
        if (msg.sender != dev){ return 1; }
        if (!devRewardClaimed){ return 1; }
        if (!migrationEnded){ return 1; }
        if (daoStakeClaimed){ return 1; }
        
        uint message = creditbitContract.mintMigrationTokens(
            _recipient, 
            realVotedSupply - creditsExchanged
        );
        if (message != 0) { return 1; }
        
        creditsExchanged += (realVotedSupply - creditsExchanged);
        daoStakeClaimed = true;
        return 0;
    }
    

    function () {
        throw;
    }
}